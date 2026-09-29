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
from scanners.burp_scanner import BurpScanner
from scanners.zap_scanner import ZAPScanner
from scanners.web_tools import NiktoScanner, TLSScanner, WhatWebScanner
from scanners.supply_chain_tools import TrivyScanner, OSVScanner, GrypeScanner
from services.aggregator import aggregator_service


SCANNER_MAP = {
    # Network and web scanning
    "nmap": NmapScanner,
    "nuclei": NucleiScanner,
    "openvas": OpenVASScanner,
    "zap": ZAPScanner,
    "nikto": NiktoScanner,
    "tlsscan": TLSScanner,
    "whatweb": WhatWebScanner,
    # Supply chain: code, dependencies and container images
    "trivy": TrivyScanner,
    "osv": OSVScanner,
    "grype": GrypeScanner,
    # Commercial tools, retained but not freely runnable
    "nessus": NessusScanner,
    "burp": BurpScanner,
}


def _run_scanner_sync(scanner, target: str) -> list[ScanVulnerability]:
    """Wrapper to run scanner scan synchronously in executor."""
    try:
        return scanner.scan(target)
    except Exception:
        logger.exception("Scanner %s failed", scanner.name)
        return []


SCANNER_WALL_CLOCK_SECONDS = 420


class OrchestratorService:
    """Manages scan lifecycle and coordinates multiple scanners."""

    def __init__(self):
        self.executor = ThreadPoolExecutor(max_workers=8)

    async def run_scan(self, scan_id: int, target: str, scanners: list[str]):
        """Execute a scan across selected scanners."""
        self._update_scan(scan_id, status="running", progress=0)

        try:
            from services.target_validation import validate_target

            await asyncio.to_thread(validate_target, target)
        except Exception as e:
            detail = getattr(e, "detail", str(e))
            logger.warning("Scan %s rejected at execution time: %s", scan_id, detail)
            self._update_scan(scan_id, status="failed", progress=100)
            return

        try:
            all_vulns: list[ScanVulnerability] = []
            selected = [n for n in scanners if n in SCANNER_MAP]
            for unknown in set(scanners) - set(selected):
                logger.warning("Unknown scanner: %s, skipping", unknown)

            running: list[str] = list(selected)
            finished = 0
            self._update_scan(scan_id, current_scanner=", ".join(running), progress=0)

            async def run_one(name: str) -> None:
                nonlocal finished
                scanner = SCANNER_MAP[name]()
                loop = asyncio.get_running_loop()
                try:
                    results = await asyncio.wait_for(
                        loop.run_in_executor(self.executor, _run_scanner_sync, scanner, target),
                        timeout=SCANNER_WALL_CLOCK_SECONDS,
                    )
                    if isinstance(results, list):
                        all_vulns.extend(results)
                except asyncio.TimeoutError:
                    logger.warning("Scanner %s exceeded %ss and was abandoned", name, SCANNER_WALL_CLOCK_SECONDS)
                    all_vulns.extend(scanner._no_result(target))
                except Exception as e:
                    logger.warning("Scanner %s failed: %s", name, e)
                finally:
                    finished += 1
                    if name in running:
                        running.remove(name)
                    self._update_scan(
                        scan_id,
                        current_scanner=", ".join(running),
                        progress=int(finished / max(len(selected), 1) * 80),
                    )

            await asyncio.gather(*(run_one(n) for n in selected))

            self._update_scan(scan_id, progress=80, current_scanner="aggregating")

            # Aggregate
            db_vulns = aggregator_service.aggregate(scan_id, all_vulns)

            # Make the findings answerable by the RAG assistant. Without this
            # step the assistant can only discuss the static CVE bundle and is
            # blind to the scan the user just ran.
            self._update_scan(scan_id, progress=90, current_scanner="indexing")
            await self._index_results(scan_id, target, db_vulns)

            # Compute stats
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            total_cvss = 0.0
            for v in db_vulns:
                if v.severity in severity_counts:
                    severity_counts[v.severity] += 1
                total_cvss += v.cvss_score or 0.0

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
            self._start_briefing(scan_id)

        except Exception:
            logger.exception("Scan %d failed", scan_id)
            self._update_scan(
                scan_id,
                status="failed",
                error_message=traceback.format_exc(),
                current_scanner="",
            )

    async def _index_results(self, scan_id: int, target: str, db_vulns: list):
        """Embed scan findings into the vector store, off the event loop.

        Embedding is CPU-bound and slow enough to stall the async loop, so it
        runs in the executor. Indexing failure must never fail the scan: the
        results are already persisted, so this is a best-effort enrichment.
        """
        if not db_vulns:
            return
        try:
            from services.rag_engine import rag_engine

            loop = asyncio.get_event_loop()
            added = await loop.run_in_executor(
                self.executor,
                rag_engine.index_scan_results,
                scan_id,
                target,
                db_vulns,
            )
            logger.info("Indexed %d scan-result chunks for scan %d", added, scan_id)
        except Exception:
            logger.exception(
                "Failed to index scan %d into the vector store; scan results are "
                "still saved but the RAG assistant will not see them",
                scan_id,
            )

    def _start_briefing(self, scan_id: int) -> None:
        from services import briefing_service

        try:
            briefing_service.mark_pending(scan_id)
            self.executor.submit(briefing_service.generate_briefing, scan_id)
        except Exception:
            logger.exception("Could not schedule the briefing for scan %d", scan_id)

    def fail_interrupted_scans(self) -> int:
        db = SessionLocal()
        try:
            stale = db.query(ScanDB).filter(ScanDB.status.in_(("pending", "running"))).all()
            for scan in stale:
                scan.status = "failed"
                scan.current_scanner = ""
                scan.error_message = "Interrupted by a backend restart."
            db.commit()
            return len(stale)
        finally:
            db.close()

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
