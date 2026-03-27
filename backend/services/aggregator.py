from scanners.base import ScanVulnerability
from models.database import VulnerabilityDB, SessionLocal


class AggregatorService:
    """Normalizes and deduplicates scanner outputs into a unified CVE/CVSS schema."""

    def aggregate(
        self, scan_id: int, raw_results: list[ScanVulnerability]
    ) -> list[VulnerabilityDB]:
        # Deduplicate by CVE ID (keep highest CVSS if duplicate)
        seen: dict[str, ScanVulnerability] = {}
        for vuln in raw_results:
            key = (
                vuln.cve_id
                or f"{vuln.affected_host}:{vuln.affected_port}:{vuln.description[:50]}"
            )
            if key in seen:
                existing = seen[key]
                if vuln.cvss_score > existing.cvss_score:
                    # Merge references before replacing
                    merged_refs = set(vuln.references)
                    merged_refs.update(existing.references)
                    vuln.references = list(merged_refs)
                    seen[key] = vuln
                else:
                    # Keep existing, merge new references into it
                    existing_refs = set(existing.references)
                    existing_refs.update(vuln.references)
                    existing.references = list(existing_refs)
            else:
                seen[key] = vuln

        # Normalize severity from CVSS score
        for vuln in seen.values():
            if vuln.cve_id and vuln.cvss_score > 0:
                vuln.severity = self._cvss_to_severity(vuln.cvss_score)

        # Persist to DB
        db = SessionLocal()
        db_vulns = []
        try:
            for vuln in seen.values():
                db_vuln = VulnerabilityDB(
                    scan_id=scan_id,
                    cve_id=vuln.cve_id,
                    cvss_score=vuln.cvss_score,
                    severity=vuln.severity,
                    description=vuln.description,
                    affected_host=vuln.affected_host,
                    affected_port=vuln.affected_port,
                    affected_service=vuln.affected_service,
                    solution=vuln.solution,
                    references=vuln.references,
                    exploit_available=vuln.exploit_available,
                    source_scanner=vuln.source_scanner,
                    raw_output=vuln.raw_output,
                )
                db.add(db_vuln)
                db_vulns.append(db_vuln)
            db.commit()
            for v in db_vulns:
                db.refresh(v)
        finally:
            db.close()

        return db_vulns

    def _cvss_to_severity(self, score: float) -> str:
        from scanners.base import ScannerAdapter

        return ScannerAdapter.parse_severity(ScannerAdapter(), score)

    def parse_severity(self, score: float) -> str:
        return self._cvss_to_severity(score)


aggregator_service = AggregatorService()
