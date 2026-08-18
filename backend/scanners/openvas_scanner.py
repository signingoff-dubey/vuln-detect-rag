from scanners.base import ScannerAdapter, ScanVulnerability


class OpenVASScanner(ScannerAdapter):
    name = "openvas"

    def is_available(self) -> bool:
        return False  # Requires full GVM setup

    def scan(self, target: str) -> list[ScanVulnerability]:
        return self._mock_scan(target)

    def _mock_scan(self, target: str) -> list[ScanVulnerability]:
        return [
            ScanVulnerability(
                cve_id="CVE-2023-36884",
                cvss_score=8.3,
                severity="HIGH",
                description="Microsoft Office and Windows HTML RCE Vulnerability",
                affected_host=target,
                affected_port=443,
                affected_service="https",
                solution="Apply Microsoft July 2023 security updates",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2023-36884"],
                source_scanner=self.name,
                raw_output={"type": "mock"}
            ),
            ScanVulnerability(
                cve_id="CVE-2022-47966",
                cvss_score=9.8,
                severity="CRITICAL",
                description="Zoho ManageEngine RCE via Apache Santuario",
                affected_host=target,
                affected_port=8443,
                affected_service="https",
                solution="Update ManageEngine products to latest versions",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2022-47966"],
                exploit_available=True,
                source_scanner=self.name,
                raw_output={"type": "mock"}
            ),
            ScanVulnerability(
                cve_id="CVE-2023-20198",
                cvss_score=10.0,
                severity="CRITICAL",
                description="Cisco IOS XE Web UI Privilege Escalation",
                affected_host=target,
                affected_port=443,
                affected_service="https",
                solution="Disable HTTP server on Cisco IOS XE, apply patches",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2023-20198"],
                exploit_available=True,
                source_scanner=self.name,
                raw_output={"type": "mock"}
            ),
            ScanVulnerability(
                cve_id="CVE-2023-22515",
                cvss_score=10.0,
                severity="CRITICAL",
                description="Confluence Data Center and Server Broken Access Control",
                affected_host=target,
                affected_port=8090,
                affected_service="http",
                solution="Upgrade Confluence to fixed versions",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2023-22515"],
                exploit_available=True,
                source_scanner=self.name,
                raw_output={"type": "mock"}
            ),
        ]
