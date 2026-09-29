"""Free web-layer scanners: Nikto, testssl.sh/sslyze, and WhatWeb.

All three are free and open source, and all three are standard parts of a
practitioner's toolkit — they cover ground Nmap and Nuclei do not:

  Nikto     misconfigurations, dangerous files, outdated server software
  testssl   TLS configuration: protocol versions, ciphers, certificate health
  WhatWeb   technology fingerprinting, which is what turns "a web server" into
            "Apache 2.4.49", the precondition for matching a CVE to a host

None of them are vulnerability scanners in the CVE sense, so most findings are
configuration weaknesses rather than CVE matches. They are reported with a
severity and no CVE ID, which the rest of the pipeline already handles.
"""

import logging
import os
import tempfile

from scanners.base import ScanVulnerability
from scanners.cli_base import CLIScannerAdapter

logger = logging.getLogger("vulndetect")


class NiktoScanner(CLIScannerAdapter):
    """Nikto web server scanner (free, GPL)."""

    name = "nikto"
    free = True
    BINARY_NAMES = ("nikto", "nikto.pl")
    PATH_ENV_VAR = "NIKTO_PATH"
    TIMEOUT = 90
    install_hint = (
        "Install with: apt install nikto / brew install nikto, or clone "
        "https://github.com/sullo/nikto"
    )

    COMMON_PATHS = {
        "win32": [r"C:\tools\nikto\program\nikto.pl"],
        "linux": ["/usr/bin/nikto", "/usr/local/bin/nikto",
                  "/opt/nikto/program/nikto.pl"],
        "darwin": ["/usr/local/bin/nikto", "/opt/homebrew/bin/nikto"],
    }

    #: Nikto's OSVDB-era output has no severity field, so findings are graded
    #: by what the check actually indicates. Keyword matching is crude but
    #: honest — the alternative is reporting everything at one level.
    HIGH_RISK_MARKERS = (
        "remote code execution", "rce", "sql injection", "command injection",
        "directory traversal", "path traversal", "file inclusion",
        "default credentials", "admin console", "shellshock",
    )
    MEDIUM_RISK_MARKERS = (
        "outdated", "cross-site", "xss", "csrf", "clickjack",
        "information disclosure", "directory indexing", "backup file",
        "phpinfo", "server leaks", "cookie without",
    )

    def scan(self, target: str) -> list[ScanVulnerability]:
        binary = self._get_binary()
        if not binary:
            logger.info("Nikto is not installed; skipping")
            return [self.unavailable_note()]

        if not self.validate_target(target, allow_url=True):
            logger.error("Nikto: rejected unsafe target %r", target)
            return []

        report_path = os.path.join(tempfile.gettempdir(), f"nikto_{os.getpid()}.json")
        host = target.replace("https://", "").replace("http://", "").split("/")[0]

        cmd = [
            binary,
            "-h", host,
            "-Format", "json",
            "-output", report_path,
            "-nointeractive",
            # Cap runtime: Nikto's full plugin set against a slow host can run
            # for a very long time.
            "-maxtime", "30s",
        ]

        result = self.run(cmd)
        if result is None:
            return []

        findings: list[ScanVulnerability] = []
        try:
            with open(report_path, "r", encoding="utf-8", errors="replace") as handle:
                data = self.parse_json(handle.read())
        except FileNotFoundError:
            data = self.parse_json(result.stdout)
        finally:
            try:
                os.unlink(report_path)
            except OSError:
                pass

        if not data:
            logger.info("Nikto returned no parseable findings for %s", target)
            return []

        # Nikto emits either a list of host objects or a single object.
        hosts = data if isinstance(data, list) else [data]
        for host_entry in hosts:
            for item in host_entry.get("vulnerabilities", []) or []:
                message = item.get("msg", "") or item.get("message", "")
                if not message:
                    continue

                severity = self._grade(message)
                cves = self.extract_cves(message)
                port = host_entry.get("port")

                findings.append(
                    ScanVulnerability(
                        cve_id=cves[0].upper() if cves else None,
                        cvss_score=self.severity_to_cvss(severity),
                        severity=severity,
                        description=message[:1000],
                        affected_host=host_entry.get("host", host),
                        affected_port=int(port) if str(port).isdigit() else None,
                        affected_service="http",
                        solution=(
                            "Review this web server finding and remove or "
                            "reconfigure the exposed resource."
                        ),
                        references=[item.get("references", "")] if item.get("references") else [],
                        source_scanner=self.name,
                        raw_output={"type": "nikto", "id": item.get("id", "")},
                    )
                )

        logger.info("Nikto reported %d findings for %s", len(findings), target)
        return findings

    def _grade(self, message: str) -> str:
        """Assign a severity band from the text of a Nikto finding."""
        lowered = message.lower()
        if any(marker in lowered for marker in self.HIGH_RISK_MARKERS):
            return "HIGH"
        if any(marker in lowered for marker in self.MEDIUM_RISK_MARKERS):
            return "MEDIUM"
        return "LOW"


class TLSScanner(CLIScannerAdapter):
    """TLS configuration review via sslyze or testssl.sh (both free)."""

    name = "tlsscan"
    free = True
    BINARY_NAMES = ("sslyze", "testssl.sh", "testssl")
    PATH_ENV_VAR = "TESTSSL_PATH"
    TIMEOUT = 600
    install_hint = (
        "Install with: pip install sslyze, or clone "
        "https://github.com/drwetter/testssl.sh"
    )

    COMMON_PATHS = {
        "win32": [r"C:\tools\testssl\testssl.sh"],
        "linux": ["/usr/bin/testssl.sh", "/usr/local/bin/testssl.sh",
                  "/opt/testssl.sh/testssl.sh"],
        "darwin": ["/usr/local/bin/testssl.sh", "/opt/homebrew/bin/testssl.sh"],
    }

    def scan(self, target: str) -> list[ScanVulnerability]:
        binary = self._get_binary()
        if not binary:
            logger.info("No TLS scanner installed; skipping")
            return [self.unavailable_note()]

        if not self.validate_target(target):
            logger.error("TLS scan: rejected unsafe target %r", target)
            return []

        if "sslyze" in binary.lower():
            return self._scan_sslyze(binary, target)
        return self._scan_testssl(binary, target)

    def _scan_sslyze(self, binary: str, target: str) -> list[ScanVulnerability]:
        """Run sslyze and interpret its JSON."""
        report_path = os.path.join(tempfile.gettempdir(), f"sslyze_{os.getpid()}.json")
        result = self.run([binary, "--json_out", report_path, f"{target}:443"])
        if result is None:
            return []

        try:
            with open(report_path, "r", encoding="utf-8", errors="replace") as handle:
                data = self.parse_json(handle.read())
        except FileNotFoundError:
            data = None
        finally:
            try:
                os.unlink(report_path)
            except OSError:
                pass

        if not data:
            return []

        findings: list[ScanVulnerability] = []
        for scan_result in data.get("server_scan_results", []):
            commands = scan_result.get("scan_result", {}) or {}

            # Deprecated protocol versions are the single most common real
            # finding: still-enabled SSLv2/v3 and TLS 1.0/1.1.
            for command, label, severity in (
                ("ssl_2_0_cipher_suites", "SSLv2", "CRITICAL"),
                ("ssl_3_0_cipher_suites", "SSLv3", "HIGH"),
                ("tls_1_0_cipher_suites", "TLS 1.0", "MEDIUM"),
                ("tls_1_1_cipher_suites", "TLS 1.1", "MEDIUM"),
            ):
                entry = (commands.get(command) or {}).get("result", {}) or {}
                accepted = entry.get("accepted_cipher_suites") or []
                if accepted:
                    findings.append(ScanVulnerability(
                        cvss_score=self.severity_to_cvss(severity),
                        severity=severity,
                        description=(
                            f"{label} is enabled with {len(accepted)} cipher "
                            f"suites. This protocol version is deprecated and "
                            f"vulnerable to known downgrade and decryption attacks."
                        ),
                        affected_host=target,
                        affected_port=443,
                        affected_service="https",
                        solution=f"Disable {label} and require TLS 1.2 or newer.",
                        source_scanner=self.name,
                        raw_output={"type": "sslyze", "protocol": label},
                    ))

            # Certificate validity.
            cert = (commands.get("certificate_info") or {}).get("result", {}) or {}
            for deployment in cert.get("certificate_deployments", []) or []:
                validation = deployment.get("path_validation_results", []) or []
                if any(not v.get("was_validation_successful", True) for v in validation):
                    findings.append(ScanVulnerability(
                        cvss_score=5.0,
                        severity="MEDIUM",
                        description=(
                            "The TLS certificate chain failed validation against "
                            "at least one trust store, so clients may see "
                            "warnings or refuse to connect."
                        ),
                        affected_host=target,
                        affected_port=443,
                        affected_service="https",
                        solution="Install a complete, currently valid certificate chain.",
                        source_scanner=self.name,
                        raw_output={"type": "sslyze", "check": "certificate"},
                    ))

        return findings

    def _scan_testssl(self, binary: str, target: str) -> list[ScanVulnerability]:
        """Run testssl.sh and interpret its JSON findings."""
        report_path = os.path.join(tempfile.gettempdir(), f"testssl_{os.getpid()}.json")
        result = self.run([
            binary, "--jsonfile", report_path, "--quiet",
            "--severity", "LOW", target,
        ])
        if result is None:
            return []

        try:
            with open(report_path, "r", encoding="utf-8", errors="replace") as handle:
                data = self.parse_json(handle.read())
        except FileNotFoundError:
            data = self.parse_json(result.stdout)
        finally:
            try:
                os.unlink(report_path)
            except OSError:
                pass

        if not isinstance(data, list):
            return []

        # testssl grades findings itself; anything below MEDIUM is mostly
        # informational output about what was tested.
        severity_map = {
            "CRITICAL": "CRITICAL", "HIGH": "HIGH",
            "MEDIUM": "MEDIUM", "LOW": "LOW",
        }

        findings: list[ScanVulnerability] = []
        for item in data:
            severity = severity_map.get((item.get("severity") or "").upper())
            if not severity:
                continue

            finding_text = item.get("finding", "")
            cves = self.extract_cves(item.get("cve", "") or finding_text)

            findings.append(ScanVulnerability(
                cve_id=cves[0].upper() if cves else None,
                cvss_score=self.severity_to_cvss(severity),
                severity=severity,
                description=f"{item.get('id', 'TLS finding')}: {finding_text}"[:1000],
                affected_host=item.get("ip", target).split("/")[0],
                affected_port=int(item.get("port", 443) or 443),
                affected_service="https",
                solution="Review and harden the TLS configuration.",
                source_scanner=self.name,
                raw_output={"type": "testssl", "id": item.get("id", "")},
            ))

        return findings


class WhatWebScanner(CLIScannerAdapter):
    """WhatWeb technology fingerprinting (free, GPL).

    Fingerprinting is not vulnerability detection, but it is what makes
    vulnerability detection possible: knowing a host runs a specific version of
    a specific product is the precondition for matching it to a CVE. Findings
    are reported at INFO severity, so they inform without inflating counts.
    """

    name = "whatweb"
    free = True
    BINARY_NAMES = ("whatweb",)
    PATH_ENV_VAR = "WHATWEB_PATH"
    TIMEOUT = 300
    install_hint = (
        "Install with: apt install whatweb, or clone "
        "https://github.com/urbanadventurer/WhatWeb"
    )

    COMMON_PATHS = {
        "win32": [r"C:\tools\whatweb\whatweb"],
        "linux": ["/usr/bin/whatweb", "/usr/local/bin/whatweb"],
        "darwin": ["/usr/local/bin/whatweb", "/opt/homebrew/bin/whatweb"],
    }

    #: Plugins that report a product version — the ones worth surfacing.
    VERSION_PLUGINS = (
        "Apache", "nginx", "IIS", "PHP", "WordPress", "Drupal", "Joomla",
        "Tomcat", "Jenkins", "OpenSSL", "jQuery", "Django", "Rails",
    )

    def scan(self, target: str) -> list[ScanVulnerability]:
        binary = self._get_binary()
        if not binary:
            logger.info("WhatWeb is not installed; skipping")
            return [self.unavailable_note()]

        if not self.validate_target(target, allow_url=True):
            logger.error("WhatWeb: rejected unsafe target %r", target)
            return []

        result = self.run([binary, "--log-json=-", "--no-errors", "-a", "1", target])
        if result is None:
            return []

        records = self.parse_jsonl(result.stdout)
        findings: list[ScanVulnerability] = []

        for record in records:
            plugins = record.get("plugins", {}) or {}
            technologies = []

            for plugin_name, detail in plugins.items():
                versions = detail.get("version") or []
                if versions and plugin_name in self.VERSION_PLUGINS:
                    technologies.append(f"{plugin_name} {'/'.join(map(str, versions))}")
                elif plugin_name in self.VERSION_PLUGINS:
                    technologies.append(plugin_name)

            if not technologies:
                continue

            findings.append(ScanVulnerability(
                cvss_score=0.0,
                severity="INFO",
                description=(
                    "Technology fingerprint: " + ", ".join(sorted(technologies))
                    + ". Version disclosure lets an attacker look up known "
                      "vulnerabilities for these exact builds."
                ),
                affected_host=record.get("target", target),
                affected_port=443 if str(record.get("target", "")).startswith("https") else 80,
                affected_service="http",
                solution=(
                    "Suppress version banners where possible and keep the "
                    "identified components patched."
                ),
                source_scanner=self.name,
                raw_output={"type": "whatweb", "technologies": technologies},
            ))

        return findings
