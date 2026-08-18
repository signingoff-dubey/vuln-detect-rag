import re
import csv
import json
import io
import ipaddress
from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from models.database import get_db, VulnerabilityDB, ScanDB, FavoriteTargetDB
from models.schemas import (
    ScanRequest,
    ScanResponse,
    ScanResultsResponse,
    VulnerabilityResponse,
    DashboardStats,
    AttackPathsResponse,
)
from services.orchestrator import orchestrator_service
from services.attack_path import attack_path_service

router = APIRouter()

TARGET_PATTERN = re.compile(
    r"^(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"
    r"|(?:\d{1,3}\.){3}\d{1,3}"
    r"|(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,})$"
)


def validate_target(target: str) -> str:
    target = target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target cannot be empty")
    if len(target) > 253:
        raise HTTPException(status_code=400, detail="Target too long")
    if not TARGET_PATTERN.match(target):
        raise HTTPException(
            status_code=400,
            detail="Invalid target. Must be a valid domain or IP address",
        )
        
    try:
        ip = ipaddress.ip_address(target)
        if ip.is_private or ip.is_loopback or ip.is_link_local or str(ip) == "169.254.169.254":
            raise HTTPException(
                status_code=400,
                detail="Scanning internal, private, or localized IP addresses is forbidden",
            )
    except ValueError:
        if target.lower() in ("localhost", "localhost.localdomain"):
            raise HTTPException(
                status_code=400,
                detail="Scanning localhost is forbidden",
            )
            
    return target


@router.post("/scans", response_model=ScanResponse)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new vulnerability scan against a target."""
    target = validate_target(request.target)
    scanners = request.scanners if request.scanners else ["nmap", "nuclei"]
    scan = orchestrator_service.create_scan(target, scanners)
    background_tasks.add_task(orchestrator_service.run_scan, scan.id, target, scanners)
    return ScanResponse.model_validate(scan)


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: int):
    """Get scan status and summary."""
    scan = orchestrator_service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanResponse.model_validate(scan)


@router.get("/scans/{scan_id}/results", response_model=ScanResultsResponse)
async def get_scan_results(scan_id: int, db: Session = Depends(get_db)):
    """Get full scan results with all vulnerabilities."""
    scan = orchestrator_service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    vulns = (
        db.query(VulnerabilityDB)
        .filter(VulnerabilityDB.scan_id == scan_id)
        .order_by(VulnerabilityDB.cvss_score.desc())
        .all()
    )

    return ScanResultsResponse(
        scan=ScanResponse.model_validate(scan),
        vulnerabilities=[VulnerabilityResponse.model_validate(v) for v in vulns],
    )


@router.get("/scans/{scan_id}/attack-paths", response_model=AttackPathsResponse)
async def get_attack_paths(scan_id: int):
    """Get computed attack paths for a scan."""
    scan = orchestrator_service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return attack_path_service.compute_attack_paths(scan_id)


@router.get("/scans/{scan_id}/export")
async def export_scan_results(
    scan_id: int,
    fmt: str = Query(default="json", alias="format", pattern="^(json|csv)$"),
    db: Session = Depends(get_db),
):
    """Export scan results as JSON or CSV."""
    scan = orchestrator_service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    vulns = (
        db.query(VulnerabilityDB)
        .filter(VulnerabilityDB.scan_id == scan_id)
        .order_by(VulnerabilityDB.cvss_score.desc())
        .all()
    )

    if fmt == "json":
        data = {
            "scan": {
                "id": scan.id,
                "target": scan.target,
                "status": scan.status,
                "total_vulnerabilities": scan.total_vulnerabilities,
                "avg_cvss": scan.avg_cvss,
                "started_at": str(scan.started_at),
                "completed_at": str(scan.completed_at) if scan.completed_at else None,
            },
            "vulnerabilities": [
                {
                    "cve_id": v.cve_id,
                    "cvss_score": v.cvss_score,
                    "severity": v.severity,
                    "description": v.description,
                    "affected_host": v.affected_host,
                    "affected_port": v.affected_port,
                    "affected_service": v.affected_service,
                    "solution": v.solution,
                    "exploit_available": v.exploit_available,
                    "source_scanner": v.source_scanner,
                    "references": v.references,
                }
                for v in vulns
            ],
        }
        content = json.dumps(data, indent=2, default=str)
        return StreamingResponse(
            io.BytesIO(content.encode()),
            media_type="application/json",
            headers={
                "Content-Disposition": f"attachment; filename=scan_{scan_id}.json"
            },
        )
    else:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            [
                "CVE ID",
                "CVSS Score",
                "Severity",
                "Description",
                "Host",
                "Port",
                "Service",
                "Solution",
                "Exploit Available",
                "Scanner",
            ]
        )
        for v in vulns:
            writer.writerow(
                [
                    v.cve_id,
                    v.cvss_score,
                    v.severity,
                    v.description,
                    v.affected_host,
                    v.affected_port,
                    v.affected_service,
                    v.solution,
                    v.exploit_available,
                    v.source_scanner,
                ]
            )
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode()),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.csv"},
        )


@router.get("/scans", response_model=list[ScanResponse])
async def list_scans(
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """List scans with pagination."""
    scans = (
        db.query(ScanDB)
        .order_by(ScanDB.started_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [ScanResponse.model_validate(s) for s in scans]


@router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    """Delete a scan and its vulnerabilities."""
    scan = db.query(ScanDB).filter(ScanDB.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()
    return {"message": f"Scan {scan_id} deleted"}


@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(db: Session = Depends(get_db)):
    """Get dashboard statistics."""
    total_scans = db.query(ScanDB).count()
    total_vulns = db.query(VulnerabilityDB).count()

    severity_counts = dict(
        db.query(VulnerabilityDB.severity, func.count(VulnerabilityDB.id))
        .group_by(VulnerabilityDB.severity)
        .all()
    )

    avg_cvss_result = db.query(func.avg(VulnerabilityDB.cvss_score)).scalar()
    avg_cvss = round(float(avg_cvss_result), 2) if avg_cvss_result else 0.0

    recent = db.query(ScanDB).order_by(ScanDB.started_at.desc()).limit(10).all()

    return DashboardStats(
        total_scans=total_scans,
        total_vulnerabilities=total_vulns,
        critical_vulns=severity_counts.get("CRITICAL", 0),
        high_vulns=severity_counts.get("HIGH", 0),
        medium_vulns=severity_counts.get("MEDIUM", 0),
        low_vulns=severity_counts.get("LOW", 0),
        avg_cvss=avg_cvss,
        recent_scans=[ScanResponse.model_validate(s) for s in recent],
    )


# --- Favorite Targets ---


@router.post("/favorites")
async def add_favorite(
    target: str = Query(...),
    label: str = Query(default=""),
    db: Session = Depends(get_db),
):
    """Add a target to favorites."""
    target = validate_target(target)
    existing = (
        db.query(FavoriteTargetDB).filter(FavoriteTargetDB.target == target).first()
    )
    if existing:
        raise HTTPException(status_code=409, detail="Target already in favorites")
    fav = FavoriteTargetDB(target=target, label=label)
    db.add(fav)
    db.commit()
    db.refresh(fav)
    return {"id": fav.id, "target": fav.target, "label": fav.label}


@router.get("/favorites")
async def list_favorites(
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """List favorite targets with pagination."""
    favs = (
        db.query(FavoriteTargetDB)
        .order_by(FavoriteTargetDB.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [{"id": f.id, "target": f.target, "label": f.label} for f in favs]


@router.delete("/favorites/{fav_id}")
async def delete_favorite(fav_id: int, db: Session = Depends(get_db)):
    """Remove a favorite target."""
    fav = db.query(FavoriteTargetDB).filter(FavoriteTargetDB.id == fav_id).first()
    if not fav:
        raise HTTPException(status_code=404, detail="Favorite not found")
    db.delete(fav)
    db.commit()
    return {"message": "Favorite removed"}
