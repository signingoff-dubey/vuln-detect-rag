"""Conversation memory for multi-turn RAG chatbot."""

import os
import json
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime
from collections import deque

logger = logging.getLogger(__name__)


@dataclass
class Message:
    """Represents a conversation message."""
    role: str
    content: str
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'role': self.role,
            'content': self.content,
            'timestamp': self.timestamp.isoformat(),
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Message':
        """Create from dictionary."""
        return cls(
            role=data['role'],
            content=data['content'],
            timestamp=datetime.fromisoformat(data['timestamp']) if 'timestamp' in data else datetime.now(),
            metadata=data.get('metadata', {})
        )


@dataclass
class ConversationContext:
    """Context for a conversation session."""
    session_id: str
    user_id: Optional[str] = None
    messages: List[Message] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_message(self, role: str, content: str, **metadata) -> Message:
        """Add message to conversation.
        
        Args:
            role: Message role (user/assistant/system)
            content: Message content
            **metadata: Additional metadata
            
        Returns:
            Created message
        """
        message = Message(role=role, content=content, metadata=metadata)
        self.messages.append(message)
        self.last_updated = datetime.now()
        return message
    
    def get_recent_messages(self, count: int = 10) -> List[Message]:
        """Get recent messages.
        
        Args:
            count: Number of messages to retrieve
            
        Returns:
            List of recent messages
        """
        return self.messages[-count:] if self.messages else []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'session_id': self.session_id,
            'user_id': self.user_id,
            'messages': [m.to_dict() for m in self.messages],
            'created_at': self.created_at.isoformat(),
            'last_updated': self.last_updated.isoformat(),
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ConversationContext':
        """Create from dictionary."""
        messages = [Message.from_dict(m) for m in data.get('messages', [])]
        return cls(
            session_id=data['session_id'],
            user_id=data.get('user_id'),
            messages=messages,
            created_at=datetime.fromisoformat(data['created_at']) if 'created_at' in data else datetime.now(),
            last_updated=datetime.fromisoformat(data['last_updated']) if 'last_updated' in data else datetime.now(),
            metadata=data.get('metadata', {})
        )


class ConversationMemory:
    """In-memory conversation memory store."""
    
    def __init__(self, max_sessions: int = 100, max_messages_per_session: int = 100):
        """Initialize conversation memory.
        
        Args:
            max_sessions: Maximum number of sessions to store
            max_messages_per_session: Maximum messages per session
        """
        self.max_sessions = max_sessions
        self.max_messages_per_session = max_messages_per_session
        self._sessions: Dict[str, ConversationContext] = {}
        self._session_order: deque = deque()
    
    def create_session(self, session_id: str, user_id: Optional[str] = None, **metadata) -> ConversationContext:
        """Create new conversation session.
        
        Args:
            session_id: Unique session ID
            user_id: Optional user ID
            **metadata: Additional session metadata
            
        Returns:
            Created conversation context
        """
        if len(self._sessions) >= self.max_sessions:
            self._evict_oldest_session()
        
        context = ConversationContext(
            session_id=session_id,
            user_id=user_id,
            metadata=metadata
        )
        
        self._sessions[session_id] = context
        self._session_order.append(session_id)
        
        logger.debug(f"Created session: {session_id}")
        return context
    
    def get_session(self, session_id: str) -> Optional[ConversationContext]:
        """Get existing session.
        
        Args:
            session_id: Session ID
            
        Returns:
            Conversation context or None
        """
        return self._sessions.get(session_id)
    
    def add_message(self, session_id: str, role: str, content: str, **metadata) -> Optional[Message]:
        """Add message to session.
        
        Args:
            session_id: Session ID
            role: Message role
            content: Message content
            **metadata: Additional metadata
            
        Returns:
            Created message or None
        """
        context = self._sessions.get(session_id)
        if not context:
            context = self.create_session(session_id)
        
        message = context.add_message(role, content, **metadata)
        
        if len(context.messages) > self.max_messages_per_session:
            excess = len(context.messages) - self.max_messages_per_session
            context.messages = context.messages[excess:]
        
        return message
    
    def get_conversation_history(self, session_id: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get conversation history for session.
        
        Args:
            session_id: Session ID
            limit: Optional message limit
            
        Returns:
            List of message dictionaries
        """
        context = self._sessions.get(session_id)
        if not context:
            return []
        
        messages = context.messages[-limit:] if limit else context.messages
        return [m.to_dict() for m in messages]
    
    def clear_session(self, session_id: str) -> bool:
        """Clear session messages.
        
        Args:
            session_id: Session ID
            
        Returns:
            True if session was cleared
        """
        if session_id in self._sessions:
            self._sessions[session_id].messages = []
            return True
        return False
    
    def delete_session(self, session_id: str) -> bool:
        """Delete entire session.
        
        Args:
            session_id: Session ID
            
        Returns:
            True if session was deleted
        """
        if session_id in self._sessions:
            del self._sessions[session_id]
            if session_id in self._session_order:
                self._session_order.remove(session_id)
            return True
        return False
    
    def _evict_oldest_session(self) -> None:
        """Evict oldest session to make room for new one."""
        if self._session_order:
            oldest = self._session_order.popleft()
            if oldest in self._sessions:
                del self._sessions[oldest]
                logger.debug(f"Evicted oldest session: {oldest}")
    
    def get_all_sessions(self) -> List[str]:
        """Get all active session IDs."""
        return list(self._sessions.keys())


class RedisConversationMemory(ConversationMemory):
    """Redis-backed conversation memory for persistence."""
    
    def __init__(self, host: str = 'localhost', port: int = 6379,
                 db: int = 0, ttl: int = 86400, **kwargs):
        """Initialize Redis-backed memory.
        
        Args:
            host: Redis host
            port: Redis port
            db: Redis database
            ttl: Session TTL in seconds
            **kwargs: Additional arguments
        """
        super().__init__(**kwargs)
        self.host = host or os.getenv('REDIS_HOST', 'localhost')
        self.port = port or int(os.getenv('REDIS_PORT', 6379))
        self.db = db
        self.ttl = ttl
        self._redis = None
    
    @property
    def redis(self):
        """Get Redis client."""
        if self._redis is None:
            try:
                import redis
                self._redis = redis.Redis(
                    host=self.host,
                    port=self.port,
                    db=self.db,
                    decode_responses=True
                )
            except ImportError:
                logger.error("Redis package not installed")
                raise
        return self._redis
    
    def create_session(self, session_id: str, user_id: Optional[str] = None, **metadata) -> ConversationContext:
        """Create session in Redis."""
        context = super().create_session(session_id, user_id, **metadata)
        self._persist_session(context)
        return context
    
    def get_session(self, session_id: str) -> Optional[ConversationContext]:
        """Get session from Redis."""
        cached = self._load_session(session_id)
        if cached:
            self._sessions[session_id] = cached
            return cached
        return self._sessions.get(session_id)
    
    def add_message(self, session_id: str, role: str, content: str, **metadata) -> Optional[Message]:
        """Add message and persist to Redis."""
        message = super().add_message(session_id, role, content, **metadata)
        if message and session_id in self._sessions:
            self._persist_session(self._sessions[session_id])
        return message
    
    def _persist_session(self, context: ConversationContext) -> None:
        """Persist session to Redis."""
        try:
            key = f"rag_session:{context.session_id}"
            data = json.dumps(context.to_dict())
            self.redis.setex(key, self.ttl, data)
        except Exception as e:
            logger.error(f"Failed to persist session: {e}")
    
    def _load_session(self, session_id: str) -> Optional[ConversationContext]:
        """Load session from Redis."""
        try:
            key = f"rag_session:{session_id}"
            data = self.redis.get(key)
            if data:
                return ConversationContext.from_dict(json.loads(data))
            return None
        except Exception as e:
            logger.error(f"Failed to load session: {e}")
            return None
    
    def delete_session(self, session_id: str) -> bool:
        """Delete session from Redis."""
        try:
            key = f"rag_session:{session_id}"
            self.redis.delete(key)
        except Exception as e:
            logger.error(f"Failed to delete session: {e}")
        return super().delete_session(session_id)


def get_conversation_memory(backend: str = 'memory', **kwargs) -> ConversationMemory:
    """Get conversation memory instance.
    
    Args:
        backend: Memory backend (memory/redis)
        **kwargs: Additional arguments
        
    Returns:
        ConversationMemory instance
    """
    if backend == 'redis':
        return RedisConversationMemory(**kwargs)
    return ConversationMemory(**kwargs)
