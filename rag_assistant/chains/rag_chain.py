"""RAG chain implementation for vulnerability analysis."""

import os
import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass

from ..vectorstore.vector_store import get_vector_store, BaseVectorStore, Document, SearchResult
from ..embeddings.embedding_service import get_embedding_service, EmbeddingService
from ..memory.conversation_memory import get_conversation_memory, ConversationMemory
from ..llm_config import get_llm_client, BaseLLMClient

logger = logging.getLogger(__name__)


@dataclass
class RAGQuery:
    """Query for RAG system."""
    question: str
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    filters: Optional[Dict[str, Any]] = None
    top_k: int = 5
    include_sources: bool = True
    conversation_history: bool = True


@dataclass
class RAGResponse:
    """Response from RAG system."""
    answer: str
    sources: List[Dict[str, Any]]
    session_id: str
    metadata: Dict[str, Any]


class RAGPipeline:
    """Main RAG pipeline for vulnerability analysis."""
    
    SYSTEM_PROMPT = """You are a cybersecurity expert assistant specializing in vulnerability analysis, remediation guidance, and exploit identification. Your role is to help security professionals understand and address security vulnerabilities.

Context:
- You have access to a comprehensive vulnerability database including CVE entries, scanner findings, and exploit information
- Your expertise covers network security, vulnerability assessment, and remediation strategies
- You provide accurate, actionable security guidance

Instructions:
1. Answer questions based on the provided context
2. Include specific CVE IDs, CVSS scores, and remediation steps when available
3. Be precise and technical in your analysis
4. If information is insufficient, acknowledge limitations
5. Prioritize critical and high severity vulnerabilities in your responses

Response format:
- Provide clear, structured answers
- Include relevant technical details
- Reference specific vulnerabilities and their characteristics
- Suggest actionable remediation steps
"""
    
    def __init__(self, vector_store: Optional[BaseVectorStore] = None,
                 embedding_service: Optional[EmbeddingService] = None,
                 llm_client: Optional[BaseLLMClient] = None,
                 conversation_memory: Optional[ConversationMemory] = None):
        """Initialize RAG pipeline.
        
        Args:
            vector_store: Vector store instance
            embedding_service: Embedding service instance
            llm_client: LLM client instance
            conversation_memory: Conversation memory instance
        """
        self.vector_store = vector_store or get_vector_store()
        self.embedding_service = embedding_service or get_embedding_service()
        self.llm_client = llm_client or get_llm_client()
        self.conversation_memory = conversation_memory or get_conversation_memory()
        
        self._initialized = False
    
    def initialize(self) -> bool:
        """Initialize RAG pipeline components.
        
        Returns:
            True if initialization successful
        """
        try:
            doc_count = self.vector_store.count()
            logger.info(f"RAG pipeline initialized with {doc_count} documents")
            self._initialized = True
            return True
        except Exception as e:
            logger.error(f"Failed to initialize RAG pipeline: {e}")
            return False
    
    def add_documents(self, documents: List[Dict[str, Any]]) -> int:
        """Add documents to the RAG system.
        
        Args:
            documents: List of document dictionaries with content and metadata
            
        Returns:
            Number of documents added
        """
        added = 0
        
        for doc_data in documents:
            content = doc_data.get('content', '')
            if not content:
                continue
            
            doc_id = doc_data.get('id', self._generate_doc_id(content))
            metadata = doc_data.get('metadata', {})
            
            try:
                embedding = self.embedding_service.embed(content)
                
                document = Document(
                    id=doc_id,
                    content=content,
                    metadata=metadata,
                    embedding=embedding
                )
                
                if self.vector_store.add_document(document):
                    added += 1
                    
            except Exception as e:
                logger.error(f"Failed to add document {doc_id}: {e}")
        
        logger.info(f"Added {added} documents to RAG system")
        return added
    
    def query(self, rag_query: RAGQuery) -> RAGResponse:
        """Process RAG query.
        
        Args:
            rag_query: RAG query object
            
        Returns:
            RAG response with answer and sources
        """
        if not self._initialized:
            self.initialize()
        
        session_id = rag_query.session_id or self._generate_session_id()
        
        try:
            query_embedding = self.embedding_service.embed(rag_query.question)
            
            search_results = self.vector_store.search(
                query_embedding=query_embedding,
                top_k=rag_query.top_k,
                filter_metadata=rag_query.filters
            )
            
            context = self._build_context(search_results)
            
            if rag_query.conversation_history:
                history = self.conversation_memory.get_conversation_history(session_id, limit=5)
                prompt = self._build_prompt_with_history(rag_query.question, context, history)
            else:
                prompt = self._build_prompt(rag_query.question, context)
            
            answer = self.llm_client.generate(prompt)
            
            self.conversation_memory.add_message(
                session_id=session_id,
                role='user',
                content=rag_query.question
            )
            self.conversation_memory.add_message(
                session_id=session_id,
                role='assistant',
                content=answer,
                sources=[s.metadata for s in search_results]
            )
            
            sources = []
            if rag_query.include_sources:
                sources = [
                    {
                        'content': r.document.content[:200] + '...' if len(r.document.content) > 200 else r.document.content,
                        'score': r.score,
                        'metadata': r.metadata
                    }
                    for r in search_results
                ]
            
            return RAGResponse(
                answer=answer,
                sources=sources,
                session_id=session_id,
                metadata={
                    'documents_retrieved': len(search_results),
                    'query_embedding_dim': len(query_embedding)
                }
            )
            
        except Exception as e:
            logger.error(f"RAG query failed: {e}")
            return RAGResponse(
                answer=f"I encountered an error processing your query: {str(e)}",
                sources=[],
                session_id=session_id,
                metadata={'error': str(e)}
            )
    
    def query_simple(self, question: str, session_id: Optional[str] = None, **kwargs) -> str:
        """Simple query interface.
        
        Args:
            question: User question
            session_id: Optional session ID
            **kwargs: Additional query parameters
            
        Returns:
            Answer string
        """
        rag_query = RAGQuery(question=question, session_id=session_id, **kwargs)
        response = self.query(rag_query)
        return response.answer
    
    def _build_context(self, search_results: List[SearchResult]) -> str:
        """Build context string from search results.
        
        Args:
            search_results: Search results
            
        Returns:
            Context string
        """
        if not search_results:
            return "No relevant documents found."
        
        context_parts = ["Context from vulnerability database:\n"]
        
        for i, result in enumerate(search_results, 1):
            metadata = result.document.metadata
            source_type = metadata.get('source_type', 'unknown')
            title = metadata.get('title', 'Untitled')
            
            context_parts.append(f"\n--- Document {i} (Relevance: {result.score:.2f}) ---")
            context_parts.append(f"Source: {source_type}")
            context_parts.append(f"Title: {title}")
            context_parts.append(f"\n{result.document.content}")
            
            if metadata.get('cve_id'):
                context_parts.append(f"CVE ID: {metadata['cve_id']}")
            if metadata.get('cvss_score'):
                context_parts.append(f"CVSS Score: {metadata['cvss_score']}")
        
        return '\n'.join(context_parts)
    
    def _build_prompt(self, question: str, context: str) -> str:
        """Build prompt without conversation history.
        
        Args:
            question: User question
            context: Retrieved context
            
        Returns:
            Formatted prompt
        """
        return f"""{self.SYSTEM_PROMPT}

{context}

User Question: {question}

Please provide a comprehensive answer based on the context above."""
    
    def _build_prompt_with_history(self, question: str, context: str,
                                   history: List[Dict[str, Any]]) -> str:
        """Build prompt with conversation history.
        
        Args:
            question: Current question
            context: Retrieved context
            history: Conversation history
            
        Returns:
            Formatted prompt with history
        """
        history_parts = ["\nConversation History:"]
        
        for msg in history[-6:]:
            role = msg.get('role', 'unknown')
            content = msg.get('content', '')
            history_parts.append(f"\n{role.capitalize()}: {content[:200]}...")
        
        return f"""{self.SYSTEM_PROMPT}

{context}

{''.join(history_parts)}

User Question: {question}

Please provide a comprehensive answer based on the context and conversation history above."""
    
    def _generate_doc_id(self, content: str) -> str:
        """Generate document ID from content."""
        import hashlib
        return hashlib.md5(content.encode()).hexdigest()[:16]
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID."""
        import uuid
        return str(uuid.uuid4())
    
    def get_stats(self) -> Dict[str, Any]:
        """Get RAG system statistics.
        
        Returns:
            Statistics dictionary
        """
        return {
            'total_documents': self.vector_store.count(),
            'active_sessions': len(self.conversation_memory.get_all_sessions()),
            'embedding_model': self.embedding_service.model,
            'llm_provider': self.llm_client.config.provider,
            'llm_model': self.llm_client.config.model
        }


class VulnerabilityRAGPipeline(RAGPipeline):
    """Specialized RAG pipeline for vulnerability analysis."""
    
    @classmethod
    def create_remediation_chain(cls) -> 'VulnerabilityRAGPipeline':
        """Create pipeline optimized for remediation queries."""
        pipeline = cls()
        pipeline.SYSTEM_PROMPT = """You are a vulnerability remediation specialist. Focus on:

1. Providing step-by-step remediation guidance
2. Prioritizing vulnerabilities by severity and impact
3. Suggesting compensating controls when immediate fixes aren't possible
4. Including relevant configuration examples and code snippets
5. Identifying dependencies and prerequisites for fixes

For each remediation recommendation:
- Explain the vulnerability and its risk
- Provide specific remediation steps
- Include configuration examples where applicable
- Note any potential impacts or side effects
"""
        return pipeline
    
    @classmethod
    def create_exploit_analysis_chain(cls) -> 'VulnerabilityRAGPipeline':
        """Create pipeline optimized for exploit analysis."""
        pipeline = cls()
        pipeline.SYSTEM_PROMPT = """You are an exploit analysis specialist. Focus on:

1. Explaining how exploits work technically
2. Identifying affected systems and versions
3. Describing attack vectors and prerequisites
4. Assessing exploitability and public availability
5. Suggesting detection and mitigation strategies

For each exploit:
- Explain the technical mechanism
- List affected versions/products
- Describe the attack requirements
- Provide detection signatures if available
"""
        return pipeline
    
    @classmethod
    def create_attack_path_chain(cls) -> 'VulnerabilityRAGPipeline':
        """Create pipeline optimized for attack path analysis."""
        pipeline = cls()
        pipeline.SYSTEM_PROMPT = """You are a network attack path analyst. Focus on:

1. Modeling potential attack chains
2. Identifying pivot points and lateral movement
3. Assessing privilege escalation paths
4. Evaluating network segmentation effectiveness
5. Recommending security controls to disrupt attack paths

For attack path analysis:
- Map source to target systems
- Identify intermediate hops
- Analyze service relationships
- Suggest path disruption strategies
"""
        return pipeline


def get_rag_pipeline(pipeline_type: str = 'default') -> RAGPipeline:
    """Get configured RAG pipeline.
    
    Args:
        pipeline_type: Type of pipeline (default, remediation, exploit, attack_path)
        
    Returns:
        Configured RAG pipeline
    """
    if pipeline_type == 'remediation':
        return VulnerabilityRAGPipeline.create_remediation_chain()
    elif pipeline_type == 'exploit':
        return VulnerabilityRAGPipeline.create_exploit_analysis_chain()
    elif pipeline_type == 'attack_path':
        return VulnerabilityRAGPipeline.create_attack_path_chain()
    else:
        return RAGPipeline()
