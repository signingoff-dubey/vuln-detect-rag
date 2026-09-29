from datetime import datetime, timezone
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Float,
    Text,
    DateTime,
    Boolean,
    JSON,
    ForeignKey,
    event,
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from config import settings

engine = create_engine(settings.DATABASE_URL, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    """Enable foreign key constraints for SQLite."""
    if "sqlite" in settings.DATABASE_URL:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def _utcnow():
    return datetime.now(timezone.utc)


class ScanDB(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target = Column(String(255), nullable=False, index=True)
    status = Column(String(50), default="pending", index=True)
    scanners_used = Column(JSON, default=list)
    total_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    avg_cvss = Column(Float, default=0.0)
    progress = Column(Integer, default=0)
    current_scanner = Column(String(50), default="")
    started_at = Column(DateTime, default=_utcnow)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)


class ScanBriefingDB(Base):
    __tablename__ = "scan_briefings"

    scan_id = Column(
        Integer, ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True
    )
    status = Column(String(20), default="pending", index=True)
    payload = Column(JSON, nullable=True)
    error = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)


class VulnerabilityDB(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(
        Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    cve_id = Column(String(50), nullable=True, index=True)
    cvss_score = Column(Float, default=0.0)
    severity = Column(String(20), default="LOW", index=True)
    description = Column(Text, default="")
    affected_host = Column(String(255), default="")
    affected_port = Column(Integer, nullable=True)
    affected_service = Column(String(100), nullable=True)
    solution = Column(Text, default="")
    references = Column(JSON, default=list)
    exploit_available = Column(Boolean, default=False)
    source_scanner = Column(String(50), default="")
    raw_output = Column(JSON, default=dict)
    created_at = Column(DateTime, default=_utcnow)


class CVEEntryDB(Base):
    __tablename__ = "cve_entries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(50), unique=True, nullable=False, index=True)
    cvss_score = Column(Float, default=0.0)
    severity = Column(String(20), default="LOW", index=True)
    description = Column(Text, default="")
    solution = Column(Text, default="")
    references = Column(JSON, default=list)
    exploit_available = Column(Boolean, default=False)
    source = Column(String(50), default="NVD")
    raw_data = Column(JSON, default=dict)
    indexed_at = Column(DateTime, default=_utcnow)


class ChatMessageDB(Base):
    __tablename__ = "chat_messages"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(100), nullable=False, index=True)
    role = Column(String(20), nullable=False)
    content = Column(Text, nullable=False)
    sources = Column(JSON, default=list)
    created_at = Column(DateTime, default=_utcnow)


class FavoriteTargetDB(Base):
    __tablename__ = "favorite_targets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target = Column(String(255), unique=True, nullable=False)
    label = Column(String(100), default="")
    created_at = Column(DateTime, default=_utcnow)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
