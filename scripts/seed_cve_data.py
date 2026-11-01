"""Seed CVE data from sample JSON files into SQLite and ChromaDB."""
import sys
import os
import json
import hashlib

# Add backend to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

from models.database import init_db, CVEEntryDB, SessionLocal
from services.rag_engine import rag_engine

#: Marks the corpus content that was last fully (re-)indexed, so a launch
#: with nothing new to seed can skip straight past enrichment (CISA KEV/EPSS/
#: NVD network lookups for every CVE) and re-embedding the whole corpus - by
#: far the slowest part of this script, and otherwise paid again on every
#: single app launch even though seeding is only here to make sure it ran
#: *at least* once.
STAMP_PATH = os.path.join(
    os.path.dirname(__file__), '..', 'backend', 'data', '.seed_stamp'
)


def _corpus_fingerprint(cve_entries: list[dict]) -> str:
    blob = json.dumps(cve_entries, sort_keys=True, default=str).encode('utf-8')
    return hashlib.sha256(blob).hexdigest()


def seed_data():
    """Load sample CVE data into database and vector store."""
    init_db()

    # Load CVE data from backend/data
    data_dir = os.path.join(os.path.dirname(__file__), '..', 'backend', 'data')
    cve_file = os.path.join(data_dir, 'sample_nvd.json')

    if not os.path.exists(cve_file):
        print(f"Error: {cve_file} not found")
        return 0

    with open(cve_file, 'r') as f:
        cve_entries = json.load(f)

    # Deduplicate by cve_id
    seen = {}
    for entry in cve_entries:
        seen[entry['cve_id']] = entry
    cve_entries = list(seen.values())

    fingerprint = _corpus_fingerprint(cve_entries)
    previous_fingerprint = None
    if os.path.exists(STAMP_PATH):
        try:
            with open(STAMP_PATH, 'r', encoding='utf-8') as f:
                previous_fingerprint = f.read().strip()
        except OSError:
            previous_fingerprint = None

    # Skip only when the corpus content is unchanged AND the vector store
    # actually has documents in it - a stamp from a run whose indexing step
    # failed, or a store that was wiped since, must not be trusted.
    if fingerprint == previous_fingerprint and rag_engine.vector_store.count() > 0:
        print(
            f"CVE corpus unchanged ({len(cve_entries)} entries) and already "
            "indexed; skipping re-enrichment and re-embedding."
        )
        return 0

    # Insert into SQLite
    db = SessionLocal()
    inserted = 0
    try:
        for entry in cve_entries:
            existing = db.query(CVEEntryDB).filter(
                CVEEntryDB.cve_id == entry['cve_id']
            ).first()

            if not existing:
                db_entry = CVEEntryDB(
                    cve_id=entry['cve_id'],
                    cvss_score=entry.get('cvss_score', 0.0),
                    severity=entry.get('severity', 'LOW'),
                    description=entry.get('description', ''),
                    solution=entry.get('solution', ''),
                    references=entry.get('references', []),
                    exploit_available=entry.get('exploit_available', False),
                    source=entry.get('source', 'NVD'),
                    raw_data=entry,
                )
                db.add(db_entry)
                try:
                    db.commit()
                    inserted += 1
                except Exception:
                    db.rollback()
    finally:
        db.close()

    # Index into ChromaDB for RAG. Report what was actually written, not what
    # was offered: printing len(cve_entries) claimed success even when every
    # single write failed, which is how a completely unreachable vector store
    # produced a clean "Indexed 50 entries" and a silently empty knowledge base.
    indexed = rag_engine.index_cves(cve_entries)

    print(f"Seeded {inserted} new CVE entries ({len(cve_entries)} total in source)")
    # One entry can yield several chunks, so this count is legitimately
    # larger than len(cve_entries). Zero is the only failure signal.
    print(f"Indexed {indexed} chunks from {len(cve_entries)} CVE entries into ChromaDB")
    if not indexed:
        print(
            "ERROR: nothing was indexed. Retrieval will return no documents and "
            "the assistant will answer without evidence. Check the vector store "
            "logs above before using the app.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    try:
        with open(STAMP_PATH, 'w', encoding='utf-8') as f:
            f.write(fingerprint)
    except OSError:
        pass  # Worst case, the next launch re-seeds unnecessarily.

    return inserted


if __name__ == "__main__":
    seed_data()
