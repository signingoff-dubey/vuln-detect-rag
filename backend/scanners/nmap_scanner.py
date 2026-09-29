import logging
import subprocess
import os
import shutil
from scanners.base import ScannerAdapter, ScanVulnerability
from config import settings

logger = logging.getLogger("vulndetect")

try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

    logger.warning("defusedxml not installed; using stdlib XML parser (less secure)")


class NmapScanner(ScannerAdapter):
    name = "nmap"

    # Common installation paths for different OS
    COMMON_PATHS = {
        "win32": [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            r"C:\nmap\nmap.exe",
            r"C:\tools\nmap\nmap.exe",
        ],
        "linux": ["/usr/bin/nmap", "/usr/local/bin/nmap"],
        "darwin": ["/usr/local/bin/nmap", "/opt/homebrew/bin/nmap"],
    }

    def _get_binary(self) -> str | None:
        """Get the nmap binary path from config or system PATH."""
        # First check config/environment variable
        path = settings.NMAP_PATH
        if path and os.path.isfile(path):
            return path
        if path and shutil.which(path):
            return path

        # Try system PATH
        result = shutil.which("nmap")
        if result:
            return result

        # Try common installation paths
        import sys

        platform = sys.platform
        for path in self.COMMON_PATHS.get(platform, []):
            if os.path.isfile(path):
                return path

        # Try other platforms too
        for paths in self.COMMON_PATHS.values():
            for path in paths:
                if os.path.isfile(path):
                    return path

        return None

    def is_available(self) -> bool:
        return self._get_binary() is not None

    @staticmethod
    def _validate_target(target: str) -> bool:
        """Validate target contains only safe characters before subprocess use."""
        import re

        return bool(re.match(r"^[a-zA-Z0-9._-]+$", target))

    def scan(self, target: str) -> list[ScanVulnerability]:
        binary = self._get_binary()
        if not binary:
            logger.warning("Nmap not available, returning no simulated data for %s", target)
            return self._no_result(target)

        if not self._validate_target(target):
            logger.error("Invalid target rejected: %s", target)
            return self._no_result(target)

        try:
            cmd = [
                binary,
                "-sV",
                "-sC",
                "--script",
                "vulners",
                "-oX",
                "-",
                "-T4",
                "--top-ports",
                "1000",
                "--version-intensity",
                "2",
                "--max-retries",
                "2",
                "--script-timeout",
                "30s",
                "--host-timeout",
                "240s",
                target,
            ]
            logger.info("Running nmap: %s", " ".join(cmd))
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if result.returncode != 0:
                logger.error(
                    "Nmap exited with code %d: %s", result.returncode, result.stderr
                )
                if result.stdout.strip():
                    vulns = self._parse_xml(result.stdout, target)
                    if vulns:
                        return vulns
                return self._no_result(target)

            vulns = self._parse_xml(result.stdout, target)
            if not vulns:
                logger.info("No CVEs found by nmap for %s, parsing open ports", target)
                vulns = self._parse_open_ports(result.stdout, target)
            return vulns
        except subprocess.TimeoutExpired:
            logger.error("Nmap scan timed out for %s", target)
            return self._no_result(target)
        except Exception:
            logger.exception("Nmap scan failed for %s", target)
            return self._no_result(target)

    def _parse_xml(self, xml_output: str, target: str) -> list[ScanVulnerability]:
        vulns = []
        try:
            root = ET.fromstring(xml_output)
            for host in root.findall(".//host"):
                hostname = host.find("hostnames/hostname")
                host_str = (
                    hostname.get("name", target) if hostname is not None else target
                )

                for port in host.findall(".//port"):
                    port_id = int(port.get("portid", 0))
                    service_el = port.find("service")
                    service_name = (
                        service_el.get("name", "") if service_el is not None else ""
                    )
                    service_product = (
                        service_el.get("product", "") if service_el is not None else ""
                    )
                    service_version = (
                        service_el.get("version", "") if service_el is not None else ""
                    )

                    for script in port.findall(".//script"):
                        script_output = script.get("output", "")
                        cves = self.extract_cves(script_output)

                        for cve in cves:
                            cvss_score = self._extract_cvss_from_script(script, cve)
                            svc_info = f"{service_product} {service_version}".strip()
                            desc = f"{cve} found on {service_name} port {port_id}"
                            if svc_info:
                                desc = f"{svc_info} vulnerable to {cve}"

                            vulns.append(
                                ScanVulnerability(
                                    cve_id=cve,
                                    cvss_score=cvss_score,
                                    severity=self.parse_severity(cvss_score),
                                    description=desc,
                                    affected_host=host_str,
                                    affected_port=port_id,
                                    affected_service=f"{service_name} ({svc_info})"
                                    if svc_info
                                    else service_name,
                                    source_scanner=self.name,
                                    raw_output={
                                        "script": script.get("id"),
                                        "output": script_output[:500],
                                    },
                                )
                            )
        except ET.ParseError as e:
            logger.warning("Failed to parse nmap XML: %s", e)
        return vulns

    def _extract_cvss_from_script(self, script, cve_id: str) -> float:
        """Extract CVSS score for a specific CVE from vulners script output."""
        try:
            # Method 1: Look for table elements with key matching the CVE and extract CVSS
            for table in script.findall(".//table"):
                table_key = table.get("key", "")
                if cve_id.upper() in table_key.upper():
                    for elem in table.findall(".//elem"):
                        if elem.get("key") == "cvss" and elem.text:
                            return float(elem.text)
                        # Also try "cvss-score" key
                        if elem.get("key") in ("cvss-score", "score") and elem.text:
                            try:
                                return float(elem.text)
                            except ValueError:
                                pass

            # Method 2: Parse CVSS from raw text output using regex
            import re

            output = script.get("output", "")
            # Pattern: CVE-XXXX-XXXX ... X.X (CVSS score often appears after CVE)
            pattern = rf"{re.escape(cve_id)}\s*.*?(\d+\.\d+)"
            match = re.search(pattern, output, re.IGNORECASE | re.DOTALL)
            if match:
                score = float(match.group(1))
                if 0.0 <= score <= 10.0:
                    return score

            # Method 3: Look for any CVSS value near the CVE in the output
            lines = output.split("\n")
            for i, line in enumerate(lines):
                if cve_id.upper() in line.upper():
                    # Check nearby lines for a CVSS score
                    context = "\n".join(lines[max(0, i - 2) : min(len(lines), i + 3)])
                    cvss_match = re.search(r"(\d+\.\d+)", context)
                    if cvss_match:
                        score = float(cvss_match.group(1))
                        if 0.0 <= score <= 10.0:
                            return score
        except (ValueError, TypeError):
            pass
        return 0.0

    def _parse_open_ports(
        self, xml_output: str, target: str
    ) -> list[ScanVulnerability]:
        findings = []
        try:
            root = ET.fromstring(xml_output)
            for host in root.findall(".//host"):
                hostname = host.find("hostnames/hostname")
                host_str = (
                    hostname.get("name", target) if hostname is not None else target
                )
                for port in host.findall(".//port"):
                    state = port.find("state")
                    if state is not None and state.get("state") == "open":
                        port_id = int(port.get("portid", 0))
                        service_el = port.find("service")
                        service_name = (
                            service_el.get("name", "unknown")
                            if service_el is not None
                            else "unknown"
                        )
                        product = (
                            service_el.get("product", "")
                            if service_el is not None
                            else ""
                        )
                        version = (
                            service_el.get("version", "")
                            if service_el is not None
                            else ""
                        )

                        desc = f"Open port {port_id}/{service_name}"
                        if product:
                            desc += f" ({product} {version})".rstrip()

                        findings.append(
                            ScanVulnerability(
                                cve_id=None,
                                cvss_score=0.0,
                                severity="INFO",
                                description=desc,
                                affected_host=host_str,
                                affected_port=port_id,
                                affected_service=service_name,
                                source_scanner=self.name,
                                raw_output={
                                    "type": "open_port",
                                    "product": product,
                                    "version": version,
                                },
                            )
                        )
        except ET.ParseError:
            pass
        return findings

