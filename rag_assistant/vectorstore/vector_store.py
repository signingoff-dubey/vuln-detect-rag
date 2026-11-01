"""Vector store implementations for RAG."""

import os
import hashlib
import logging
import tempfile
import threading
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


@dataclass
class Document:
    """Document for embedding and retrieval."""
    id: str
    content: str
    metadata: Dict[str, Any]
    embedding: Optional[List[float]] = None


@dataclass
class SearchResult:
    """Search result with similarity score."""
    document: Document
    score: float
    metadata: Dict[str, Any]


class BaseVectorStore(ABC):
    """Abstract base class for vector stores."""
    
    def __init__(self, collection_name: str = "vulnerability_docs"):
        """Initialize vector store.
        
        Args:
            collection_name: Name of collection
        """
        self.collection_name = collection_name
    
    @abstractmethod
    def add_document(self, document: Document) -> bool:
        """Add document to store.
        
        Args:
            document: Document to add
            
        Returns:
            True if successful
        """
        pass
    
    @abstractmethod
    def add_documents(self, documents: List[Document]) -> bool:
        """Add multiple documents.
        
        Args:
            documents: Documents to add
            
        Returns:
            True if successful
        """
        pass
    
    @abstractmethod
    def search(self, query_embedding: List[float], top_k: int = 5,
               filter_metadata: Optional[Dict[str, Any]] = None) -> List[SearchResult]:
        """Search for similar documents.
        
        Args:
            query_embedding: Query embedding vector
            top_k: Number of results
            filter_metadata: Optional metadata filters
            
        Returns:
            List of search results
        """
        pass
    
    @abstractmethod
    def delete(self, document_id: str) -> bool:
        """Delete document by ID.
        
        Args:
            document_id: Document ID
            
        Returns:
            True if successful
        """
        pass
    
    @abstractmethod
    def get_document(self, document_id: str) -> Optional[Document]:
        """Get document by ID.
        
        Args:
            document_id: Document ID
            
        Returns:
            Document or None
        """
        pass
    
    @abstractmethod
    def count(self) -> int:
        """Get total document count.

        Returns:
            Document count
        """
        pass

    def delete_where(self, filter_metadata: Dict[str, Any]) -> int:
        """Delete documents matching a metadata filter.

        Backends that cannot support this return 0.
        """
        return 0


#: Collection name used by every component that talks to the vector store.
#: Kept in one place so the writer (indexing) and the reader (retrieval) can
#: never drift apart — a mismatch here silently yields an empty knowledge base.
DEFAULT_COLLECTION = os.getenv('CHROMA_COLLECTION', 'cve_knowledge')


class ChromaVectorStore(BaseVectorStore):
    """ChromaDB vector store implementation."""

    def __init__(self, collection_name: Optional[str] = None,
                 persist_directory: Optional[str] = None,
                 host: Optional[str] = None, port: int = 8000):
        """Initialize ChromaDB store.

        Args:
            collection_name: Collection name
            persist_directory: Local persistence directory
            host: Remote host
            port: Remote port
        """
        super().__init__(collection_name or DEFAULT_COLLECTION)

        default_persist_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'backend', 'data', 'chroma'))
        self.persist_directory = persist_directory or os.getenv('VECTOR_STORE_PATH', default_persist_dir)
        self.host = host or os.getenv('CHROMA_HOST', 'localhost')
        self.port = port or int(os.getenv('CHROMA_PORT', 8000))

        self._client = None
        self._collection = None

    @property
    def client(self):
        """Get or create ChromaDB client.

        Uses PersistentClient so documents survive a restart. A bare
        ``Client(Settings(persist_directory=...))`` does NOT persist: Chroma's
        ``is_persistent`` defaults to False, so that form is in-memory only and
        every restart starts from an empty collection.
        """
        if self._client is None:
            try:
                import chromadb

                # Chroma posts anonymised usage events to its own endpoint by
                # default. This is a vulnerability platform whose operators are
                # told the datastore makes no outbound calls, so the dependency's
                # default is switched off rather than documented as an exception.
                telemetry_off = chromadb.config.Settings(anonymized_telemetry=False)

                remote_host = os.getenv('CHROMA_HOST')
                if remote_host:
                    self._client = chromadb.HttpClient(
                        host=remote_host, port=self.port, settings=telemetry_off,
                    )
                    logger.info("Using remote ChromaDB at %s:%s", remote_host, self.port)
                else:
                    os.makedirs(self.persist_directory, exist_ok=True)
                    self._client = chromadb.PersistentClient(
                        path=self.persist_directory, settings=telemetry_off,
                    )
                    logger.info("Using persistent ChromaDB at %s", self.persist_directory)
            except ImportError:
                logger.error("ChromaDB package not installed")
                raise
        return self._client
    
    @property
    def collection(self):
        """Get or create collection."""
        if self._collection is None:
            try:
                self._collection = self.client.get_or_create_collection(
                    name=self.collection_name,
                    metadata={"hnsw:space": "cosine"}
                )
            except Exception as e:
                logger.error(f"Failed to get/create collection: {e}")
                raise
        return self._collection
    
    def add_document(self, document: Document) -> bool:
        """Add single document to store."""
        return self.add_documents([document])

    def add_documents(self, documents: List[Document]) -> bool:
        """Add multiple documents.

        Embeddings computed by our own EmbeddingService are handed to Chroma
        explicitly. Without this Chroma silently falls back to its own default
        embedding function, so writes and reads end up in different vector
        spaces and similarity scores become meaningless.

        Uses upsert so re-indexing the same corpus updates rows instead of
        raising on duplicate IDs.
        """
        try:
            if not documents:
                return True

            ids = [doc.id for doc in documents]
            contents = [doc.content for doc in documents]
            metadatas = [self._clean_metadata(doc.metadata) for doc in documents]
            embeddings = [doc.embedding for doc in documents]

            payload = {
                "ids": ids,
                "documents": contents,
                "metadatas": metadatas,
            }
            if all(e is not None for e in embeddings):
                payload["embeddings"] = embeddings
            else:
                missing = sum(1 for e in embeddings if e is None)
                logger.warning(
                    "%d/%d documents have no embedding; letting Chroma embed them "
                    "(this can mismatch the query embedding space)",
                    missing, len(documents),
                )

            self.collection.upsert(**payload)

            logger.info(f"Upserted {len(documents)} documents into ChromaDB "
                        f"collection '{self.collection_name}'")
            return True

        except Exception as e:
            logger.error(f"Failed to add documents: {e}")
            return False

    @staticmethod
    def _clean_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Coerce metadata to Chroma-safe scalars.

        Chroma only accepts str/int/float/bool/None. Lists (e.g. references)
        and dicts are flattened rather than dropped so they stay filterable.
        """
        clean: Dict[str, Any] = {}
        for key, value in (metadata or {}).items():
            if value is None or isinstance(value, (str, int, float, bool)):
                clean[key] = value
            elif isinstance(value, (list, tuple, set)):
                clean[key] = ", ".join(str(v) for v in value)
            else:
                clean[key] = str(value)
        return clean

    def search(self, query_embedding: List[float], top_k: int = 5,
               filter_metadata: Optional[Dict[str, Any]] = None) -> List[SearchResult]:
        """Search for similar documents."""
        try:
            available = self.count()
            if available == 0:
                logger.warning(
                    "Vector store collection '%s' is empty — no documents to retrieve. "
                    "Run the CVE seeding script to populate it.",
                    self.collection_name,
                )
                return []

            results = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=min(top_k, available),
                where=filter_metadata or None,
            )

            search_results = []
            if results and results.get('documents'):
                for i, doc_content in enumerate(results['documents'][0]):
                    metadata = results['metadatas'][0][i] if results.get('metadatas') else {}
                    distance = results['distances'][0][i] if results.get('distances') else 0
                    doc_id = results['ids'][0][i] if results.get('ids') else ''

                    document = Document(
                        id=doc_id,
                        content=doc_content,
                        metadata=metadata or {},
                        embedding=None
                    )

                    search_results.append(SearchResult(
                        document=document,
                        score=self._distance_to_score(distance),
                        metadata=metadata or {}
                    ))

            return search_results

        except Exception as e:
            logger.error(f"Search failed: {e}")
            return []

    @staticmethod
    def _distance_to_score(distance: Optional[float]) -> float:
        """Convert a cosine distance into a 0..1 similarity score.

        The collection is created with ``hnsw:space = cosine``, so distance is
        in [0, 2]. The old ``1 - distance`` mapping produced negative scores for
        anything past orthogonal, which broke score thresholding.
        """
        if distance is None:
            return 0.0
        return max(0.0, min(1.0, 1.0 - (float(distance) / 2.0)))

    def delete_where(self, filter_metadata: Dict[str, Any]) -> int:
        """Delete every document matching a metadata filter.

        Used to re-index a scan without accumulating stale duplicates.
        """
        try:
            existing = self.collection.get(where=filter_metadata)
            ids = existing.get('ids', []) if existing else []
            if ids:
                self.collection.delete(ids=ids)
            return len(ids)
        except Exception as e:
            logger.error(f"Failed to delete by filter {filter_metadata}: {e}")
            return 0
    
    def delete(self, document_id: str) -> bool:
        """Delete document by ID."""
        try:
            self.collection.delete(ids=[document_id])
            return True
        except Exception as e:
            logger.error(f"Failed to delete document: {e}")
            return False
    
    def get_document(self, document_id: str) -> Optional[Document]:
        """Get document by ID."""
        try:
            results = self.collection.get(ids=[document_id])
            if results and results.get('documents'):
                return Document(
                    id=document_id,
                    content=results['documents'][0],
                    metadata=results['metadatas'][0] if results.get('metadatas') else {},
                    embedding=None
                )
            return None
        except Exception as e:
            logger.error(f"Failed to get document: {e}")
            return None
    
    def count(self) -> int:
        """Get document count."""
        try:
            return self.collection.count()
        except Exception as e:
            logger.error(f"Failed to count documents: {e}")
            return 0


class FAISSVectorStore(BaseVectorStore):
    """FAISS vector store implementation."""
    
    def __init__(self, collection_name: Optional[str] = None,
                 index_path: Optional[str] = None):
        """Initialize FAISS store.

        Args:
            collection_name: Collection name
            index_path: Path to save/load index
        """
        collection_name = collection_name or DEFAULT_COLLECTION
        super().__init__(collection_name)
        # tempfile.gettempdir() rather than a hardcoded /tmp so the index also
        # works on Windows, which is this project's primary target.
        self.index_path = index_path or os.path.join(
            tempfile.gettempdir(), f"faiss_{collection_name}"
        )

        self._index = None
        self._dimension: Optional[int] = None
        self._documents: Dict[str, Document] = {}
        self._doc_ids: List[str] = []
        # Guards every read/write of _index, _doc_ids and _documents: the
        # orchestrator indexes scan results from an 8-worker thread pool, so
        # two scans finishing close together can otherwise race on this
        # instance - interleaved appends corrupting _doc_ids, or a search
        # running mid-rebuild against a half-updated index.
        self._lock = threading.RLock()
        self._load_index()

    def _ensure_index(self, dimension: int):
        """Create the index once the true embedding dimension is known.

        The dimension is taken from the first embedding rather than hardcoded:
        all-MiniLM-L6-v2 is 384-dim, nomic-embed-text is 768, OpenAI is 1536.
        A fixed constant silently corrupts every store but one.
        """
        if self._index is None:
            import faiss
            self._dimension = dimension
            self._index = faiss.IndexFlatIP(dimension)
            logger.info("Created FAISS index with dimension %d", dimension)
        elif self._dimension != dimension:
            raise ValueError(
                f"Embedding dimension {dimension} does not match existing FAISS "
                f"index dimension {self._dimension}. Delete {self.index_path} "
                f"to rebuild after changing the embedding model."
            )
        return self._index

    @property
    def index(self):
        """Get the FAISS index (must have been created by _ensure_index)."""
        if self._index is None:
            raise RuntimeError(
                "FAISS index not initialized — add documents before searching."
            )
        return self._index

    def add_document(self, document: Document) -> bool:
        """Add single document."""
        return self.add_documents([document])

    def add_documents(self, documents: List[Document]) -> bool:
        """Add multiple documents.

        A document whose id already exists is an update, not an insert:
        IndexFlatIP has no in-place replace, so re-indexing the same id (as
        the orchestrator does every time a scan completes, since indexing
        upserts) previously just appended a second vector for it forever,
        skewing retrieval toward whatever got re-indexed most. When any
        incoming id collides with one already stored, the whole index is
        rebuilt from the deduplicated document set instead.
        """
        try:
            import numpy as np
            import faiss

            with self._lock:
                embeddable = [doc for doc in documents if doc.embedding]
                needs_rebuild = any(doc.id in self._documents for doc in embeddable)

                for doc in embeddable:
                    self._documents[doc.id] = doc

                if needs_rebuild:
                    self._rebuild_index()
                else:
                    for doc in embeddable:
                        index = self._ensure_index(len(doc.embedding))
                        embedding = np.array([doc.embedding], dtype=np.float32)
                        faiss.normalize_L2(embedding)
                        index.add(embedding)
                        self._doc_ids.append(doc.id)

                logger.info(f"Added {len(embeddable)} documents to FAISS")
                return self._save_index()

        except Exception as e:
            logger.error(f"Failed to add documents: {e}")
            return False

    def _rebuild_index(self) -> None:
        """Rebuild the FAISS index from the current (deduplicated) documents.

        Must be called with ``self._lock`` held.
        """
        import numpy as np
        import faiss

        self._index = None
        self._dimension = None
        self._doc_ids = []

        ids, vectors = [], []
        for doc_id, doc in self._documents.items():
            if doc.embedding:
                ids.append(doc_id)
                vectors.append(doc.embedding)
        if not vectors:
            return

        index = self._ensure_index(len(vectors[0]))
        matrix = np.array(vectors, dtype=np.float32)
        faiss.normalize_L2(matrix)
        index.add(matrix)
        self._doc_ids = ids
    
    def search(self, query_embedding: List[float], top_k: int = 5,
               filter_metadata: Optional[Dict[str, Any]] = None) -> List[SearchResult]:
        """Search for similar documents."""
        try:
            import numpy as np
            import faiss

            with self._lock:
                if self._index is None or not self._doc_ids:
                    logger.warning("FAISS index is empty — no documents to retrieve.")
                    return []

                query = np.array([query_embedding], dtype=np.float32)
                faiss.normalize_L2(query)

                distances, indices = self.index.search(query, min(top_k, len(self._doc_ids)))

                results = []
                for i, idx in enumerate(indices[0]):
                    if idx < len(self._doc_ids):
                        doc_id = self._doc_ids[idx]
                        doc = self._documents.get(doc_id)
                        if doc:
                            if filter_metadata:
                                if not self._matches_filter(doc.metadata, filter_metadata):
                                    continue

                            results.append(SearchResult(
                                document=doc,
                                score=float(distances[0][i]),
                                metadata=doc.metadata
                            ))

                return results

        except Exception as e:
            logger.error(f"Search failed: {e}")
            return []
    
    def _matches_filter(self, metadata: Dict[str, Any], filter_dict: Dict[str, Any]) -> bool:
        """Check if metadata matches filter."""
        for key, value in filter_dict.items():
            if key not in metadata or metadata[key] != value:
                return False
        return True
    
    def delete(self, document_id: str) -> bool:
        """Delete document (FAISS doesn't support direct deletion)."""
        logger.warning("FAISS doesn't support document deletion")
        return False
    
    def get_document(self, document_id: str) -> Optional[Document]:
        """Get document by ID."""
        return self._documents.get(document_id)
    
    def count(self) -> int:
        """Get document count."""
        with self._lock:
            return len(self._documents)
    
    def _save_index(self) -> bool:
        """Save index to disk.

        Writes each file to a sibling .tmp path and os.replace()s it into
        place, rather than writing the live path directly: a reader (or a
        concurrent save) opening index.faiss mid-write would otherwise see a
        truncated, unreadable file. os.replace is atomic on both POSIX and
        Windows, so the live file is always either the old or the new
        complete version, never a partial one.
        """
        try:
            import json
            import faiss
            from dataclasses import asdict

            os.makedirs(self.index_path, exist_ok=True)

            index_path = f"{self.index_path}/index.faiss"
            index_tmp = f"{index_path}.tmp"
            faiss.write_index(self.index, index_tmp)
            os.replace(index_tmp, index_path)

            payload = {
                "doc_ids": list(self._doc_ids),
                "documents": {k: asdict(d) for k, d in self._documents.items()},
            }
            docs_path = f"{self.index_path}/documents.json"
            docs_tmp = f"{docs_path}.tmp"
            with open(docs_tmp, 'w', encoding='utf-8') as f:
                json.dump(payload, f)
            os.replace(docs_tmp, docs_path)

            return True
        except Exception as e:
            logger.error(f"Failed to save index: {e}")
            return False
    
    def _load_index(self) -> bool:
        """Load index from disk.

        Called from __init__ so a persisted index is actually reused; previously
        this existed but was never invoked, so every process started empty.
        """
        try:
            index_file = os.path.join(self.index_path, "index.faiss")
            docs_file = os.path.join(self.index_path, "documents.json")
            if not os.path.exists(index_file):
                return False

            import json
            import faiss

            self._index = faiss.read_index(index_file)
            self._dimension = self._index.d

            if os.path.exists(docs_file):
                with open(docs_file, 'r', encoding='utf-8') as f:
                    payload = json.load(f)
                self._doc_ids = list(payload["doc_ids"])
                self._documents = {
                    k: Document(**v) for k, v in payload["documents"].items()
                }

            logger.info("Loaded FAISS index (%d vectors) from %s",
                        len(self._doc_ids), self.index_path)
            return True
        except Exception as e:
            logger.error(f"Failed to load index: {e}")
            return False

    def delete_where(self, filter_metadata: Dict[str, Any]) -> int:
        """FAISS IndexFlatIP has no stable deletion; rebuild is required."""
        logger.warning("FAISS backend does not support metadata deletion")
        return 0


class VectorStoreFactory:
    """Factory for creating vector stores."""
    
    @staticmethod
    def create(store_type: Optional[str] = None, **kwargs) -> BaseVectorStore:
        """Create vector store instance.
        
        Args:
            store_type: Type of store (chroma/faiss)
            **kwargs: Additional arguments
            
        Returns:
            Vector store instance
        """
        store_type = store_type or os.getenv('VECTOR_STORE_TYPE', 'chroma').lower()
        
        if store_type == 'chroma':
            return ChromaVectorStore(**kwargs)
        elif store_type == 'faiss':
            return FAISSVectorStore(**kwargs)
        else:
            raise ValueError(f"Unknown vector store type: {store_type}")


def get_vector_store(**kwargs) -> BaseVectorStore:
    """Get configured vector store.
    
    Args:
        **kwargs: Additional arguments
        
    Returns:
        Vector store instance
    """
    return VectorStoreFactory.create(**kwargs)
