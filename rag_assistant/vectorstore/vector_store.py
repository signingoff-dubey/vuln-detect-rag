"""Vector store implementations for RAG."""

import os
import hashlib
import logging
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


class ChromaVectorStore(BaseVectorStore):
    """ChromaDB vector store implementation."""
    
    def __init__(self, collection_name: str = "vulnerabilities",
                 persist_directory: Optional[str] = None,
                 host: Optional[str] = None, port: int = 8000):
        """Initialize ChromaDB store.
        
        Args:
            collection_name: Collection name
            persist_directory: Local persistence directory
            host: Remote host
            port: Remote port
        """
        super().__init__(collection_name)
        
        default_persist_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'backend', 'data', 'chroma'))
        self.persist_directory = persist_directory or os.getenv('VECTOR_STORE_PATH', default_persist_dir)
        self.host = host or os.getenv('CHROMA_HOST', 'localhost')
        self.port = port or int(os.getenv('CHROMA_PORT', 8000))
        
        self._client = None
        self._collection = None
    
    @property
    def client(self):
        """Get or create ChromaDB client."""
        if self._client is None:
            try:
                import chromadb
                from chromadb.config import Settings
                
                if os.path.exists(self.persist_directory):
                    self._client = chromadb.Client(Settings(
                        persist_directory=self.persist_directory,
                        anonymized_telemetry=False
                    ))
                else:
                    self._client = chromadb.HttpClient(
                        host=self.host,
                        port=self.port
                    )
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
        """Add multiple documents."""
        try:
            if not documents:
                return True
            
            ids = [doc.id for doc in documents]
            contents = [doc.content for doc in documents]
            metadatas = [doc.metadata for doc in documents]
            embeddings = [doc.embedding for doc in documents if doc.embedding]
            
            self.collection.add(
                ids=ids,
                documents=contents,
                metadatas=metadatas
            )
            
            logger.info(f"Added {len(documents)} documents to ChromaDB")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add documents: {e}")
            return False
    
    def search(self, query_embedding: List[float], top_k: int = 5,
               filter_metadata: Optional[Dict[str, Any]] = None) -> List[SearchResult]:
        """Search for similar documents."""
        try:
            results = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=top_k,
                where=filter_metadata
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
                        metadata=metadata,
                        embedding=None
                    )
                    
                    score = 1 - distance if distance is not None else 0
                    
                    search_results.append(SearchResult(
                        document=document,
                        score=score,
                        metadata=metadata
                    ))
            
            return search_results
            
        except Exception as e:
            logger.error(f"Search failed: {e}")
            return []
    
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
    
    def __init__(self, collection_name: str = "vulnerability_docs",
                 index_path: Optional[str] = None):
        """Initialize FAISS store.
        
        Args:
            collection_name: Collection name
            index_path: Path to save/load index
        """
        super().__init__(collection_name)
        self.index_path = index_path or f"/tmp/faiss_{collection_name}"
        
        self._index = None
        self._documents: Dict[str, Document] = {}
        self._doc_ids: List[str] = []
    
    @property
    def index(self):
        """Get or create FAISS index."""
        if self._index is None:
            try:
                import faiss
                dimension = 1536
                self._index = faiss.IndexFlatIP(dimension)
            except ImportError:
                logger.error("FAISS package not installed")
                raise
        return self._index
    
    def add_document(self, document: Document) -> bool:
        """Add single document."""
        return self.add_documents([document])
    
    def add_documents(self, documents: List[Document]) -> bool:
        """Add multiple documents."""
        try:
            import numpy as np
            import faiss
            
            for doc in documents:
                if doc.embedding:
                    self._documents[doc.id] = doc
                    self._doc_ids.append(doc.id)
                    
                    embedding = np.array([doc.embedding], dtype=np.float32)
                    faiss.normalize_L2(embedding)
                    self.index.add(embedding)
            
            logger.info(f"Added {len(documents)} documents to FAISS")
            return self._save_index()
            
        except Exception as e:
            logger.error(f"Failed to add documents: {e}")
            return False
    
    def search(self, query_embedding: List[float], top_k: int = 5,
               filter_metadata: Optional[Dict[str, Any]] = None) -> List[SearchResult]:
        """Search for similar documents."""
        try:
            import numpy as np
            import faiss
            
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
        return len(self._documents)
    
    def _save_index(self) -> bool:
        """Save index to disk."""
        try:
            import faiss
            import pickle
            
            os.makedirs(self.index_path, exist_ok=True)
            faiss.write_index(self.index, f"{self.index_path}/index.faiss")
            
            with open(f"{self.index_path}/documents.pkl", 'wb') as f:
                pickle.dump((self._documents, self._doc_ids), f)
            
            return True
        except Exception as e:
            logger.error(f"Failed to save index: {e}")
            return False
    
    def _load_index(self) -> bool:
        """Load index from disk."""
        try:
            import faiss
            import pickle
            
            if os.path.exists(f"{self.index_path}/index.faiss"):
                self._index = faiss.read_index(f"{self.index_path}/index.faiss")
                
            if os.path.exists(f"{self.index_path}/documents.pkl"):
                with open(f"{self.index_path}/documents.pkl", 'rb') as f:
                    self._documents, self._doc_ids = pickle.load(f)
            
            return True
        except Exception as e:
            logger.error(f"Failed to load index: {e}")
            return False


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
