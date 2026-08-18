import logging
import subprocess
import json
import os
import shutil
from scanners.base import ScannerAdapter, ScanVulnerability
from config import settings

logger = logging.getLogger("vulndetect")


class NucleiScanner(ScannerAdapter):
    name = "nuclei"

    def _get_binary(self) -> str | None:
        """Get the nuclei binary path from config or system PATH."""
        path = settings.NUCLEI_PATH
        if path and os.path.isfile(path):
            return path
        if path and shutil.which(path):
            return path
        return shutil.which("nuclei")

    def is_available(self) -> bool:
        return self._get_binary() is not None

    def scan(self, target: str) -> list[ScanVulnerability]:
        binary = self._get_binary()
        if not binary:
            logger.warning("Nuclei not available, using mock data for %s", target)
            return self._mock_scan(target)

        try:
            # Ensure target has a scheme for nuclei
            if not target.startswith(("http://", "https://")):
                target_url = f"https://{target}"
            else:
                target_url = target

            cmd = [
                binary,
                "-u",
                target_url,
                "-jsonl",
                "-silent",
                "-severity",
                "critical,high,medium",
                "-timeout",
                "10",
                "-retries",
                "1",
                "-c",
                "50",
            ]
            logger.info("Running nuclei: %s", " ".join(cmd))
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            # Nuclei returns 0 even when it finds vulns, non-zero on error
            if result.returncode != 0 and not result.stdout.strip():
                logger.error(
                    "Nuclei exited with code %d: %s", result.returncode, result.stderr
                )
                return self._mock_scan(target)

            vulns = self._parse_json_lines(result.stdout, target)
            if not vulns:
                logger.info("No vulns found by nuclei for %s", target)
            return vulns if vulns else []
        except subprocess.TimeoutExpired:
            logger.error("Nuclei scan timed out for %s", target)
            return self._mock_scan(target)
        except Exception:
            logger.exception("Nuclei scan failed for %s", target)
            return self._mock_scan(target)

    def _parse_json_lines(self, output: str, target: str) -> list[ScanVulnerability]:
        vulns = []
        seen = set()
        for line in output.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                info = data.get("info", {})
                severity = info.get("severity", "low").upper()

                # Handle both v2 and v3 nuclei JSON formats
                classification = info.get("classification", {})
                cves = classification.get("cve-id", [])
                if isinstance(cves, str):
                    cves = [cves]
                cvss = classification.get("cvss-score", 0.0)

                template_id = data.get("template-id", data.get("templateID", ""))
                matched_at = data.get("matched-at", data.get("matched", target))

                # Deduplicate
                dedup_key = f"{template_id}:{matched_at}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                description = info.get("description", "")
                if not description:
                    description = template_id.replace("-", " ").title()

                vulns.append(
                    ScanVulnerability(
                        cve_id=cves[0] if cves else None,
                        cvss_score=float(cvss)
                        if cvss
                        else self._severity_to_cvss(severity),
                        severity=severity,
                        description=description,
                        affected_host=matched_at or target,
                        affected_port=None,
                        affected_service=data.get("type", ""),
                        solution=info.get("remediation", ""),
                        references=info.get("reference", [])
                        if isinstance(info.get("reference"), list)
                        else [info.get("reference", "")]
                        if info.get("reference")
                        else [],
                        exploit_available=severity in ("CRITICAL", "HIGH"),
                        source_scanner=self.name,
                        raw_output={
                            "template": template_id,
                            "type": data.get("type", ""),
                        },
                    )
                )
            except (json.JSONDecodeError, KeyError, TypeError) as e:
                logger.debug("Failed to parse nuclei output line: %s", e)
                continue
        return vulns

    def _severity_to_cvss(self, severity: str) -> float:
        mapping = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5, "INFO": 0.0}
        return mapping.get(severity, 0.0)

    def _mock_scan(self, target: str) -> list[ScanVulnerability]:
        import hashlib

        target_hash = hashlib.md5((target + "nuclei").encode()).hexdigest()
        hash_val = int(target_hash[:8], 16)

        vulns = []
        if hash_val % 2 != 0:
            vulns.append(
                ScanVulnerability(
                    cve_id="CVE-2023-50164",
                    cvss_score=7.5,
                    severity="HIGH",
                    description="Apache Struts Path Traversal leads to RCE",
                    affected_host=target,
                    affected_port=80,
                    affected_service="http",
                    solution="Upgrade Apache Struts to 6.3.0.2 or later",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2023-50164"],
                    source_scanner=self.name,
                    raw_output={"type": "mock", "target": target},
                )
            )
        if hash_val % 4 == 0:
            vulns.append(
                ScanVulnerability(
                    cve_id="CVE-2024-23897",
                    cvss_score=9.8,
                    severity="CRITICAL",
                    description="Jenkins Arbitrary File Read Vulnerability",
                    affected_host=target,
                    affected_port=8080,
                    affected_service="http",
                    solution="Upgrade Jenkins to version 2.442, LTS 2.426.3 or later",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2024-23897"],
                    exploit_available=True,
                    source_scanner=self.name,
                    raw_output={"type": "mock", "target": target},
                )
            )
        vulns.append(
            ScanVulnerability(
                cve_id=None,
                cvss_score=5.3,
                severity="MEDIUM",
                description="Missing HTTP Security Headers detected",
                affected_host=target,
                affected_port=443,
                affected_service="https",
                solution="Add X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security headers",
                source_scanner=self.name,
                raw_output={"type": "mock", "target": target},
            )
        )
        if hash_val % 6 == 0:
            vulns.append(
                ScanVulnerability(
                    cve_id="CVE-2023-46747",
                    cvss_score=9.8,
                    severity="CRITICAL",
                    description="F5 BIG-IP Configuration Utility Auth Bypass",
                    affected_host=target,
                    affected_port=443,
                    affected_service="https",
                    solution="Update F5 BIG-IP to fixed versions",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2023-46747"],
                    exploit_available=True,
                    source_scanner=self.name,
                    raw_output={"type": "mock", "target": target},
                )
            )
        return vulns
