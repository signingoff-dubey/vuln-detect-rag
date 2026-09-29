import logging

from models.database import ScanBriefingDB, SessionLocal, VulnerabilityDB, ScanDB

logger = logging.getLogger("vulndetect")


def _set(scan_id: int, **fields) -> None:
    db = SessionLocal()
    try:
        row = db.get(ScanBriefingDB, scan_id)
        if row is None:
            row = ScanBriefingDB(scan_id=scan_id)
            db.add(row)
        for key, value in fields.items():
            setattr(row, key, value)
        db.commit()
    finally:
        db.close()


def mark_pending(scan_id: int) -> None:
    _set(scan_id, status="generating", payload=None, error=None)


def get_briefing(scan_id: int) -> dict:
    db = SessionLocal()
    try:
        row = db.get(ScanBriefingDB, scan_id)
        if row is None:
            return {"status": "none"}
        result = {"status": row.status, "error": row.error}
        if row.payload:
            result.update(row.payload)
        return result
    finally:
        db.close()


def generate_briefing(scan_id: int) -> None:
    """Write and store the default briefing for a finished scan."""
    from services.rag_engine import rag_engine

    mark_pending(scan_id)
    db = SessionLocal()
    try:
        scan = db.get(ScanDB, scan_id)
        if scan is None:
            _set(scan_id, status="failed", error="Scan not found")
            return
        vulns = (
            db.query(VulnerabilityDB)
            .filter(VulnerabilityDB.scan_id == scan_id)
            .order_by(VulnerabilityDB.cvss_score.desc())
            .all()
        )
        payload = rag_engine.explain_scan(scan_id, scan.target, vulns, None)
    except Exception as exc:
        logger.exception("Briefing for scan %d failed", scan_id)
        _set(scan_id, status="failed", error=str(exc))
        return
    finally:
        db.close()

    if payload.get("error") and not payload.get("explanation"):
        _set(scan_id, status="failed", payload=payload, error=payload["error"])
    else:
        _set(scan_id, status="ready", payload=payload, error=None)
    logger.info("Briefing for scan %d stored (%s)", scan_id, "ready" if payload.get("explanation") else "failed")
