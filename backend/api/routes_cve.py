from fastapi import APIRouter, HTTPException, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from models.database import get_db, CVEEntryDB
from models.schemas import CVEResponse

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
router = APIRouter()


def _escape_like(value: str) -> str:
    """Escape special characters for SQL LIKE patterns."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


# NOTE: /cve/stats/severity must be defined BEFORE /cve/{cve_id}
# otherwise FastAPI matches "stats" as a cve_id parameter.
@router.get("/cve/stats/severity")
async def cve_severity_stats(db: Session = Depends(get_db)):
    """Get CVE counts by severity."""
    counts = dict(
        db.query(CVEEntryDB.severity, func.count(CVEEntryDB.id))
        .group_by(CVEEntryDB.severity)
        .all()
    )
    return counts


@router.get("/cve/{cve_id}", response_model=CVEResponse)
async def get_cve(cve_id: str, db: Session = Depends(get_db)):
    """Look up a specific CVE by ID."""
    entry = db.query(CVEEntryDB).filter(CVEEntryDB.cve_id == cve_id.upper()).first()
    if not entry:
        raise HTTPException(
            status_code=404, detail=f"CVE {cve_id} not found in database"
        )
    return CVEResponse.model_validate(entry)


@router.get("/cve", response_model=list[CVEResponse])
async def search_cves(
    q: str = Query(default=""),
    severity: str = Query(default=""),
    exploit_only: bool = Query(default=False),
    limit: int = Query(default=50, le=200),
    db: Session = Depends(get_db),
):
    """Search CVEs by keyword, severity, or exploit availability."""
    query = db.query(CVEEntryDB)
    if q:
        escaped_q = _escape_like(q)
        query = query.filter(CVEEntryDB.description.ilike(f"%{escaped_q}%", escape="\\"))
    if severity:
        sev = severity.upper()
        if sev not in VALID_SEVERITIES:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid severity. Must be one of: {VALID_SEVERITIES}",
            )
        query = query.filter(CVEEntryDB.severity == sev)
    if exploit_only:
        query = query.filter(CVEEntryDB.exploit_available.is_(True))
    results = query.order_by(CVEEntryDB.cvss_score.desc()).limit(limit).all()
    return [CVEResponse.model_validate(r) for r in results]
