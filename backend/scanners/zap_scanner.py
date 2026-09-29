import logging
import subprocess
import json
import os
import shutil
import tempfile
import time
from scanners.base import ScannerAdapter, ScanVulnerability
from config import settings

logger = logging.getLogger("vulndetect")


class ZAPScanner(ScannerAdapter):
    """OWASP ZAP (Zed Attack Proxy) scanner adapter.

    ZAP is a free, open-source web application security scanner.
    It can be run via CLI (zap.sh / zap.bat) or via its REST API.

    Supports both active and passive scanning modes.
    """

    name = "zap"

    # Common installation paths for different OS
    COMMON_PATHS = {
        "win32": [
            r"C:\Program Files\OWASP\Zed Attack Proxy\zap.bat",
            r"C:\Program Files (x86)\OWASP\Zed Attack Proxy\zap.bat",
            r"C:\tools\zap\zap.bat",
            r"C:\ZAP\zap.bat",
        ],
        "linux": [
            "/usr/bin/zap.sh",
            "/usr/share/zaproxy/zap.sh",
            "/opt/zaproxy/zap.sh",
            "/snap/bin/zaproxy",
        ],
        "darwin": [
            "/Applications/OWASP ZAP.app/Contents/Java/zap.sh",
            "/usr/local/bin/zap.sh",
            "/opt/homebrew/bin/zap.sh",
        ],
    }

    # ZAP API configuration
    API_HOST = "127.0.0.1"
    API_PORT = 8080
    API_KEY = ""  # Set in .env if authentication is enabled

    def _get_binary(self) -> str | None:
        """Get the ZAP binary path from config or system PATH."""
        # First check config/environment variable
        path = settings.ZAP_PATH
        if path and os.path.isfile(path):
            return path
        if path and shutil.which(path):
            return path

        # Try system PATH
        for name in ["zap.sh", "zap.bat", "zaproxy", "zap"]:
            result = shutil.which(name)
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
        """Check if ZAP is available on the system."""
        return self._get_binary() is not None

    def scan(self, target: str) -> list[ScanVulnerability]:
        """Run an OWASP ZAP scan against the target.

        ZAP supports:
        - Active scanning: Actively tests for vulnerabilities
        - Passive scanning: Analyzes traffic without attacking
        - Spider: Crawls the website to find all pages
        """
        binary = self._get_binary()
        if not binary:
            logger.warning("OWASP ZAP not available, returning no simulated data for %s", target)
            return self._no_result(target)

        # Try REST API first (if ZAP is already running)
        try:
            vulns = self._scan_via_api(target)
            if vulns:
                return vulns
        except Exception as e:
            logger.debug("ZAP API not available: %s", e)

        # Try CLI mode
        try:
            vulns = self._scan_via_cli(target)
            if vulns:
                return vulns
        except Exception as e:
            logger.debug("ZAP CLI not available: %s", e)

        # No usable result; report that honestly
        logger.info("OWASP ZAP scan not possible, returning no simulated data for %s", target)
        return self._no_result(target)

    SPIDER_WAIT_SECONDS = 60
    ACTIVE_WAIT_SECONDS = 120

    @staticmethod
    def _resolve_url(target: str) -> str:
        """Pick the scheme the host actually answers on, preferring HTTPS."""
        import httpx

        if target.startswith(("http://", "https://")):
            return target
        for scheme in ("https", "http"):
            try:
                httpx.get(f"{scheme}://{target}", timeout=8, follow_redirects=False, verify=True)
                return f"{scheme}://{target}"
            except httpx.HTTPError:
                continue
        return f"http://{target}"

    def _scan_via_api(self, target: str) -> list[ScanVulnerability]:
        """Scan using ZAP REST API, with bounded spider and active-scan phases."""
        import httpx

        base_url = f"http://{self.API_HOST}:{self.API_PORT}"
        key = {"apikey": self.API_KEY} if self.API_KEY else {}
        target_url = self._resolve_url(target)

        def call(path: str, **params):
            response = httpx.get(f"{base_url}{path}", params={**params, **key}, timeout=30)
            response.raise_for_status()
            return response.json()

        def wait(status_path: str, scan_id: str, budget: int, step: int) -> None:
            deadline = time.time() + budget
            while time.time() < deadline:
                time.sleep(step)
                if str(call(status_path, scanId=scan_id).get("status")) == "100":
                    return

        spider_id = call("/JSON/spider/action/scan/", url=target_url).get("scan", "0")
        wait("/JSON/spider/view/status/", spider_id, self.SPIDER_WAIT_SECONDS, 3)
        call("/JSON/spider/action/stop/", scanId=spider_id)

        active_id = call("/JSON/ascan/action/scan/", url=target_url).get("scan", "0")
        wait("/JSON/ascan/view/status/", active_id, self.ACTIVE_WAIT_SECONDS, 5)
        call("/JSON/ascan/action/stop/", scanId=active_id)

        data = call("/JSON/core/view/alerts/")
        prefix = target_url.rstrip("/")
        data["alerts"] = [
            a for a in data.get("alerts", [])
            if str(a.get("url") or a.get("nodeName") or "").startswith(prefix)
        ]
        return self._parse_api_results(data, target)

    def _parse_api_results(self, data: dict, target: str) -> list[ScanVulnerability]:
        """Parse ZAP API results into ScanVulnerability objects."""
        vulns = []
        alerts = data.get("alerts", [])

        seen = set()
        for alert in alerts:
            alert_name = alert.get("name") or alert.get("alert", "")
            if alert_name in seen:
                continue
            seen.add(alert_name)

            risk = alert.get("risk", "Informational").upper()
            confidence = alert.get("confidence", "Medium").upper()

            # Map ZAP risk levels
            risk_mapping = {
                "INFORMATIONAL": "INFO",
                "LOW": "LOW",
                "MEDIUM": "MEDIUM",
                "HIGH": "HIGH",
            }
            severity = risk_mapping.get(risk, "MEDIUM")

            cvss_score = self._severity_to_cvss(severity)
            if confidence == "HIGH":
                cvss_score = min(cvss_score + 0.5, 10.0)

            cve_id = None
            cwe_id = alert.get("cweid", "")
            if cwe_id:
                # ZAP uses CWE IDs, not CVE IDs
                description = f"CWE-{cwe_id}: {alert_name}"
            else:
                description = alert_name

            solution = alert.get("solution", "")
            references = []
            ref = alert.get("reference", "")
            if ref:
                references = [r.strip() for r in ref.split("\n") if r.strip()]

            for instance in (alert.get("instances") or [alert])[:1]:
                vulns.append(
                    ScanVulnerability(
                        cve_id=cve_id,
                        cvss_score=cvss_score,
                        severity=severity,
                        description=description,
                        affected_host=target,
                        affected_port=None,
                        affected_service=instance.get("method", "GET"),
                        solution=solution,
                        references=references,
                        exploit_available=severity in ("CRITICAL", "HIGH"),
                        source_scanner=self.name,
                        raw_output={"type": "api", "alert": alert},
                    )
                )
                break  # One entry per alert type

        return vulns

    def _scan_via_cli(self, target: str) -> list[ScanVulnerability]:
        """Scan using a locally launched ZAP instance.

        Two routes, in order of reliability:

        1. Start ZAP in daemon mode and drive it through the same REST API the
           remote path uses. This gives structured JSON alerts.
        2. Fall back to `-quickurl`, which writes a JSON report to disk.

        Both produce parseable JSON; neither depends on scraping console output.
        """
        binary = self._get_binary()
        target_url = target if target.startswith("http") else f"https://{target}"

        if self._start_daemon():
            try:
                return self._scan_via_api(target)
            finally:
                self._stop_daemon()

        # tempfile.gettempdir() rather than a hardcoded /tmp: this project is
        # Windows-primary, where /tmp does not exist, so the report was
        # previously never written or read back.
        report_path = os.path.join(tempfile.gettempdir(), "zap_report.json")

        cmd = [
            binary,
            "-quickurl",
            target_url,
            "-quickout",
            report_path,
            "-quickprogress",
            "-cmd",
        ]

        logger.info("Running ZAP quick scan: %s", " ".join(cmd))
        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )

        try:
            with open(report_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return self._parse_api_results(data, target)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.warning("ZAP produced no readable report: %s", e)
            return []

    def _start_daemon(self) -> bool:
        """Start ZAP in daemon mode so the REST API becomes usable.

        ZAP's console output is unstructured and version-dependent, so scraping
        it was never going to work — the previous `_parse_cli_output` returned
        an empty list unconditionally, which meant the CLI path silently always
        fell through to mock data. Launching the daemon and using the same JSON
        API as the remote path removes the parsing problem entirely.
        """
        binary = self._get_binary()
        if not binary:
            return False

        cmd = [
            binary,
            "-daemon",
            "-host", self.API_HOST,
            "-port", str(self.API_PORT),
            "-config", "api.disablekey=true",
            # Passive-scan-only startup; the active scan is driven through the
            # API once the daemon is up.
            "-config", "api.addrs.addr.name=.*",
            "-config", "api.addrs.addr.regex=true",
        ]
        logger.info("Starting ZAP daemon: %s", " ".join(cmd))

        try:
            self._daemon = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except OSError as e:
            logger.error("Could not start the ZAP daemon: %s", e)
            return False

        # ZAP takes 20-60s to become responsive depending on the machine.
        return self._await_daemon(timeout=120)

    def _await_daemon(self, timeout: int = 120) -> bool:
        """Poll the ZAP API until it answers or the budget runs out."""
        import httpx

        deadline = time.time() + timeout
        url = f"http://{self.API_HOST}:{self.API_PORT}/JSON/core/view/version/"

        while time.time() < deadline:
            try:
                response = httpx.get(url, timeout=5)
                if response.status_code == 200:
                    logger.info("ZAP daemon ready: version %s",
                                response.json().get("version", "unknown"))
                    return True
            except Exception:
                pass
            time.sleep(3)

        logger.error("ZAP daemon did not become ready within %ds", timeout)
        return False

    def _stop_daemon(self) -> None:
        """Shut down a daemon this adapter started."""
        daemon = getattr(self, "_daemon", None)
        if daemon is None:
            return
        try:
            import httpx

            httpx.get(
                f"http://{self.API_HOST}:{self.API_PORT}/JSON/core/action/shutdown/",
                timeout=10,
            )
            daemon.wait(timeout=30)
        except Exception:
            logger.debug("Graceful ZAP shutdown failed; terminating", exc_info=True)
            try:
                daemon.terminate()
            except Exception:
                pass
        finally:
            self._daemon = None

    def _severity_to_cvss(self, severity: str) -> float:
        """Convert ZAP risk level to CVSS score."""
        mapping = {
            "CRITICAL": 9.5,
            "HIGH": 7.5,
            "MEDIUM": 5.0,
            "LOW": 2.5,
            "INFO": 0.0,
            "INFORMATIONAL": 0.0,
        }
        return mapping.get(severity, 0.0)

