from scanners.base import ScannerAdapter, ScanVulnerability


class NessusScanner(ScannerAdapter):
    name = "nessus"

    def is_available(self) -> bool:
        return False  # Requires Nessus installation

    def scan(self, target: str) -> list[ScanVulnerability]:
        return self._mock_scan(target)

    def _mock_scan(self, target: str) -> list[ScanVulnerability]:
        return [
            ScanVulnerability(
                cve_id="CVE-2021-26855",
                cvss_score=9.8,
                severity="CRITICAL",
                description="Microsoft Exchange Server SSRF (ProxyLogon)",
                affected_host=target,
                affected_port=443,
                affected_service="https",
                solution="Apply Microsoft Exchange March 2021 security updates",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-26855"],
                exploit_available=True,
                source_scanner=self.name,
                raw_output={"type": "mock"}
            ),
            ScanVulnerability(
                cve_id="CVE-2023-4966",
                cvss_score=7.5,
                severity="HIGH",
                description="Citrix NetScaler ADC and Gateway Session Hijacking (Citrix Bleed)",
                affected_host=target,
                affected_port=443,
                affected_service="https",
                solution="Update NetScaler ADC and Gateway to patched versions",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2023-4966"],
                exploit_available=True,
                source_scanner=self.name,
                raw_output={"type": "mock"}
            ),
            ScanVulnerability(
                cve_id="CVE-2023-27997",
                cvss_score=9.8,
                severity="CRITICAL",
                description="Fortinet FortiOS SSL-VPN Heap-Based Buffer Overflow",
                affected_host=target,
                affected_port=10443,
                affected_service="https",
                solution="Upgrade FortiOS to patched version",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2023-27997"],
                exploit_available=True,
                source_scanner=self.name,
                raw_output={"type": "mock"}
            ),
            ScanVulnerability(
                cve_id="CVE-2024-3400",
                cvss_score=10.0,
                severity="CRITICAL",
                description="PAN-OS GlobalProtect Command Injection",
                affected_host=target,
                affected_port=443,
                affected_service="https",
                solution="Apply Palo Alto Networks security patches",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2024-3400"],
                exploit_available=True,
                source_scanner=self.name,
                raw_output={"type": "mock"}
            ),
            ScanVulnerability(
                cve_id="CVE-2023-1389",
                cvss_score=7.5,
                severity="HIGH",
                description="TP-Link Archer AX21 Command Injection",
                affected_host=target,
                affected_port=80,
                affected_service="http",
                solution="Firmware update from TP-Link",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2023-1389"],
                source_scanner=self.name,
                raw_output={"type": "mock"}
            ),
        ]
