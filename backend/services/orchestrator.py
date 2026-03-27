import asyncio
import logging
import traceback
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

from models.database import ScanDB, SessionLocal

logger = logging.getLogger("vulndetect")
from scanners.base import ScanVulnerability
from scanners.nmap_scanner import NmapScanner
from scanners.nuclei_scanner import NucleiScanner
from scanners.openvas_scanner import OpenVASScanner
from scanners.nessus_scanner import NessusScanner
from services.aggregator import aggregator_service


SCANNER_MAP = {
    "nmap": NmapScanner,
    "nuclei": NucleiScanner,
    "openvas": OpenVASScanner,
    "nessus": NessusScanner,
}


class OrchestratorService:
    """Manages scan lifecycle and coordinates multiple scanners."""

    def __init__(self):
        self.executor = ThreadPoolExecutor(max_workers=4)

    async def run_scan(self, scan_id: int, target: str, scanners: list[str]):
        """Execute a scan across selected scanners."""
        self._update_scan(scan_id, status="running", progress=0)

        try:
            all_vulns: list[ScanVulnerability] = []
            total_scanners = len(scanners)

            for idx, scanner_name in enumerate(scanners):
                scanner_cls = SCANNER_MAP.get(scanner_name)
                if not scanner_cls:
                    logger.warning("Unknown scanner: %s, skipping", scanner_name)
                    continue

                self._update_scan(
                    scan_id,
                    current_scanner=scanner_name,
                    progress=int((idx / total_scanners) * 80),
                )

                scanner = scanner_cls()
                loop = asyncio.get_running_loop()
                results = await loop.run_in_executor(
                    self.executor, scanner.scan, target
                )
                if isinstance(results, list):
                    all_vulns.extend(results)

            self._update_scan(scan_id, progress=80, current_scanner="aggregating")

            # Aggregate
            db_vulns = aggregator_service.aggregate(scan_id, all_vulns)

            # Compute stats
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            total_cvss = 0.0
            for v in db_vulns:
                severity_counts[v.severity] = severity_counts.get(v.severity, 0) + 1
                total_cvss += (v.cvss_score or 0.0)

            avg_cvss = round(total_cvss / len(db_vulns), 2) if db_vulns else 0.0

            # Update scan record
            self._update_scan(
                scan_id,
                status="completed",
                progress=100,
                current_scanner="",
                total_vulnerabilities=len(db_vulns),
                critical_count=severity_counts["CRITICAL"],
                high_count=severity_counts["HIGH"],
                medium_count=severity_counts["MEDIUM"],
                low_count=severity_counts["LOW"],
                avg_cvss=avg_cvss,
                completed_at=datetime.now(timezone.utc),
            )

        except Exception:
            logger.exception("Scan %d failed", scan_id)
            self._update_scan(
                scan_id,
                status="failed",
                error_message=traceback.format_exc(),
                current_scanner="",
            )

    def create_scan(self, target: str, scanners: list[str]) -> ScanDB:
        db = SessionLocal()
        try:
            scan = ScanDB(
                target=target,
                scanners_used=scanners,
                status="pending",
            )
            db.add(scan)
            db.commit()
            db.refresh(scan)
            db.expunge(scan)
            return scan
        finally:
            db.close()

    def get_scan(self, scan_id: int) -> ScanDB | None:
        db = SessionLocal()
        try:
            scan = db.query(ScanDB).filter(ScanDB.id == scan_id).first()
            if scan:
                db.expunge(scan)
            return scan
        finally:
            db.close()

    def get_all_scans(self) -> list[ScanDB]:
        db = SessionLocal()
        try:
            scans = db.query(ScanDB).order_by(ScanDB.started_at.desc()).all()
            for scan in scans:
                db.expunge(scan)
            return scans
        finally:
            db.close()

    def _update_scan(self, scan_id: int, **kwargs):
        db = SessionLocal()
        try:
            scan = db.query(ScanDB).filter(ScanDB.id == scan_id).first()
            if scan:
                for key, value in kwargs.items():
                    setattr(scan, key, value)
                db.commit()
        finally:
            db.close()

    def shutdown(self):
        self.executor.shutdown(wait=False)


orchestrator_service = OrchestratorService()
