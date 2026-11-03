"""Free supply-chain scanners: Trivy, OSV-Scanner and Grype.

These answer a different question from the network scanners. Nmap and Nuclei
ask "what is exposed on this host"; these ask "what vulnerable software is in
this codebase, image, or dependency tree". In practice most CVEs an
organisation carries arrive through dependencies rather than through exposed
services, so a vulnerability platform that only looks at the network sees a
fraction of the real exposure.

All three are free and open source:

  Trivy         Aqua Security. Containers, filesystems, IaC, secrets, SBOM.
  OSV-Scanner   Google. Lockfile and SBOM scanning against the OSV database.
  Grype         Anchore. Container images and filesystems.

Because they scan artefacts rather than hosts, they take a path or an image
reference as their target, not a hostname. When handed a hostname they say so
rather than pretending to have scanned something.
"""

import logging
import os

from scanners.base import ScanVulnerability
from scanners.cli_base import CLIScannerAdapter

logger = logging.getLogger("vulndetect")


class ArtefactScannerMixin:
    """Shared handling for tools that scan a path or image, not a host."""

    def resolve_artefact(self, target: str) -> str | None:
        """Interpret the target as a filesystem path or container image.

        Returns None when the target is clearly a hostname, which these tools
        cannot scan.
        """
        explicit = os.getenv("SCAN_ARTEFACT_PATH", "")
        if explicit:
            return explicit

        if os.path.exists(target):
            return target

        # Image references look like "nginx:1.25" or "registry/org/img:tag" and
        # are legitimate targets; a bare hostname is not.
        if ":" in target and "/" in target:
            return target
        if ":" in target and not target.replace(".", "").isdigit():
            return target

        return None

    def not_applicable(self, target: str) -> ScanVulnerability:
        """Explain why an artefact scanner produced nothing for a hostname."""
        return ScanVulnerability(
            cvss_score=0.0,
            severity="INFO",
            description=(
                f"{self.name} scans code, container images and dependency "
                f"manifests, not network hosts, so it had nothing to examine "
                f"for '{target}'. Point it at a project directory or an image "
                f"reference by setting SCAN_ARTEFACT_PATH."
            ),
            affected_host=target,
            source_scanner=self.name,
            raw_output={"type": "not_applicable"},
        )


class TrivyScanner(ArtefactScannerMixin, CLIScannerAdapter):
    """Trivy: container, filesystem and dependency scanning (free, Apache-2.0)."""

    name = "trivy"
    free = True
    BINARY_NAMES = ("trivy",)
    PATH_ENV_VAR = "TRIVY_PATH"
    TIMEOUT = 900
    install_hint = (
        "Install with: brew install trivy / apt install trivy, or see "
        "https://aquasecurity.github.io/trivy"
    )

    COMMON_PATHS = {
        "win32": [r"C:\tools\trivy\trivy.exe", r"C:\Program Files\trivy\trivy.exe"],
        "linux": ["/usr/bin/trivy", "/usr/local/bin/trivy"],
        "darwin": ["/usr/local/bin/trivy", "/opt/homebrew/bin/trivy"],
    }

    def scan(self, target: str) -> list[ScanVulnerability]:
        binary = self._get_binary()
        if not binary:
            logger.info("Trivy is not installed; skipping")
            return [self.unavailable_note()]

        artefact = self.resolve_artefact(target)
        if not artefact:
            return [self.not_applicable(target)]

        # "fs" handles both a directory and an image that has been unpacked;
        # "image" is used when the target looks like an image reference.
        subcommand = "image" if not os.path.exists(artefact) else "fs"
        result = self.run([
            binary, subcommand,
            "--format", "json",
            "--quiet",
            "--scanners", "vuln,secret,misconfig",
            artefact,
        ])
        if result is None:
            return []

        data = self.parse_json(result.stdout)
        if not data:
            logger.info("Trivy reported nothing for %s", artefact)
            return []

        findings: list[ScanVulnerability] = []

        for block in data.get("Results", []) or []:
            location = block.get("Target", artefact)

            for vuln in block.get("Vulnerabilities", []) or []:
                severity = (vuln.get("Severity") or "UNKNOWN").upper()
                cvss_score = self._best_cvss(vuln) or self.severity_to_cvss(severity)
                package = vuln.get("PkgName", "unknown package")
                installed = vuln.get("InstalledVersion", "")
                fixed = vuln.get("FixedVersion", "")

                findings.append(ScanVulnerability(
                    cve_id=(vuln.get("VulnerabilityID") or "").upper() or None,
                    cvss_score=cvss_score,
                    severity=self.parse_severity(cvss_score) if cvss_score else severity,
                    description=(
                        f"{package} {installed}: "
                        f"{vuln.get('Title') or vuln.get('Description', '')}"
                    )[:1000],
                    affected_host=location,
                    affected_service=package,
                    solution=(
                        f"Upgrade {package} to {fixed}." if fixed
                        else f"No fixed version is published for {package} yet; "
                             f"consider removing or replacing the dependency."
                    ),
                    references=(vuln.get("References") or [])[:5],
                    exploit_available=False,  # version match, not evidence of an exploit
                    source_scanner=self.name,
                    raw_output={
                        "type": "trivy",
                        "package": package,
                        "installed": installed,
                        "fixed": fixed,
                    },
                ))

            # Hardcoded secrets are frequently a more urgent problem than any
            # single dependency CVE, so they are reported as CRITICAL.
            for secret in block.get("Secrets", []) or []:
                findings.append(ScanVulnerability(
                    cvss_score=9.0,
                    severity="CRITICAL",
                    description=(
                        f"Hardcoded secret detected: {secret.get('Title', 'unknown')} "
                        f"in {location} at line {secret.get('StartLine', '?')}."
                    ),
                    affected_host=location,
                    solution=(
                        "Remove the secret from source control, rotate the "
                        "credential, and load it from the environment instead."
                    ),
                    source_scanner=self.name,
                    raw_output={"type": "trivy_secret",
                                "rule": secret.get("RuleID", "")},
                ))

            for misconfig in block.get("Misconfigurations", []) or []:
                severity = (misconfig.get("Severity") or "MEDIUM").upper()
                findings.append(ScanVulnerability(
                    cvss_score=self.severity_to_cvss(severity),
                    severity=severity,
                    description=(
                        f"Misconfiguration {misconfig.get('ID', '')}: "
                        f"{misconfig.get('Title', '')}"
                    )[:1000],
                    affected_host=location,
                    solution=misconfig.get("Resolution", ""),
                    source_scanner=self.name,
                    raw_output={"type": "trivy_misconfig",
                                "id": misconfig.get("ID", "")},
                ))

        logger.info("Trivy reported %d findings for %s", len(findings), artefact)
        return findings

    @staticmethod
    def _best_cvss(vuln: dict) -> float:
        """Highest CVSS v3 base score across the vendors Trivy aggregates."""
        best = 0.0
        for entry in (vuln.get("CVSS") or {}).values():
            score = entry.get("V3Score") or entry.get("V2Score") or 0
            try:
                best = max(best, float(score))
            except (TypeError, ValueError):
                continue
        return best


class OSVScanner(ArtefactScannerMixin, CLIScannerAdapter):
    """Google's OSV-Scanner for dependency manifests (free, Apache-2.0)."""

    name = "osv"
    free = True
    BINARY_NAMES = ("osv-scanner",)
    PATH_ENV_VAR = "OSV_SCANNER_PATH"
    TIMEOUT = 600
    install_hint = (
        "Install with: brew install osv-scanner, or download from "
        "https://github.com/google/osv-scanner/releases"
    )

    COMMON_PATHS = {
        "win32": [r"C:\tools\osv-scanner\osv-scanner.exe"],
        "linux": ["/usr/bin/osv-scanner", "/usr/local/bin/osv-scanner"],
        "darwin": ["/usr/local/bin/osv-scanner", "/opt/homebrew/bin/osv-scanner"],
    }

    def scan(self, target: str) -> list[ScanVulnerability]:
        binary = self._get_binary()
        if not binary:
            logger.info("OSV-Scanner is not installed; skipping")
            return [self.unavailable_note()]

        artefact = self.resolve_artefact(target)
        if not artefact or not os.path.exists(artefact):
            return [self.not_applicable(target)]

        # OSV-Scanner exits non-zero when it finds vulnerabilities, so the exit
        # code is not an error signal here — only empty output is.
        result = self.run([
            binary, "--format", "json", "--recursive", artefact,
        ])
        if result is None:
            return []

        data = self.parse_json(result.stdout)
        if not data:
            return []

        findings: list[ScanVulnerability] = []

        for package_result in data.get("results", []) or []:
            source = (package_result.get("source") or {}).get("path", artefact)

            for package_entry in package_result.get("packages", []) or []:
                package = package_entry.get("package", {}) or {}
                package_name = package.get("name", "unknown")
                package_version = package.get("version", "")
                ecosystem = package.get("ecosystem", "")

                for vuln in package_entry.get("vulnerabilities", []) or []:
                    # OSV IDs are often GHSA; the CVE alias is the useful one.
                    aliases = vuln.get("aliases", []) or []
                    cve_id = next(
                        (a.upper() for a in aliases if a.upper().startswith("CVE-")),
                        None,
                    )
                    severity = self._severity_of(vuln)
                    cvss_score = self.severity_to_cvss(severity)

                    findings.append(ScanVulnerability(
                        cve_id=cve_id,
                        cvss_score=cvss_score,
                        severity=severity,
                        description=(
                            f"{ecosystem} package {package_name} {package_version}: "
                            f"{vuln.get('summary') or vuln.get('details', '')}"
                        )[:1000],
                        affected_host=source,
                        affected_service=package_name,
                        solution=(
                            f"Update {package_name} to a version outside the "
                            f"affected range ({vuln.get('id', '')})."
                        ),
                        references=[
                            r.get("url", "") for r in (vuln.get("references") or [])[:5]
                        ],
                        source_scanner=self.name,
                        raw_output={
                            "type": "osv",
                            "osv_id": vuln.get("id", ""),
                            "package": package_name,
                            "ecosystem": ecosystem,
                        },
                    ))

        logger.info("OSV-Scanner reported %d findings for %s", len(findings), artefact)
        return findings

    @staticmethod
    def _severity_of(vuln: dict) -> str:
        """Read a severity band from OSV's database-specific fields."""
        severity = (
            (vuln.get("database_specific") or {}).get("severity")
            or (vuln.get("ecosystem_specific") or {}).get("severity")
            or ""
        )
        if severity:
            severity = severity.upper()
            # GitHub advisories say MODERATE. Passed through as-is it matched
            # no band, scored CVSS 0, and dropped out of every severity count.
            return {"MODERATE": "MEDIUM", "IMPORTANT": "HIGH"}.get(severity, severity)
        # No severity published: MEDIUM avoids both silently hiding it and
        # overstating it.
        return "MEDIUM"


class GrypeScanner(ArtefactScannerMixin, CLIScannerAdapter):
    """Anchore Grype: image and filesystem vulnerability scanning (free)."""

    name = "grype"
    free = True
    BINARY_NAMES = ("grype",)
    PATH_ENV_VAR = "GRYPE_PATH"
    TIMEOUT = 900
    install_hint = (
        "Install with: brew install grype, or see "
        "https://github.com/anchore/grype"
    )

    COMMON_PATHS = {
        "win32": [r"C:\tools\grype\grype.exe"],
        "linux": ["/usr/bin/grype", "/usr/local/bin/grype"],
        "darwin": ["/usr/local/bin/grype", "/opt/homebrew/bin/grype"],
    }

    def scan(self, target: str) -> list[ScanVulnerability]:
        binary = self._get_binary()
        if not binary:
            logger.info("Grype is not installed; skipping")
            return [self.unavailable_note()]

        artefact = self.resolve_artefact(target)
        if not artefact:
            return [self.not_applicable(target)]

        reference = f"dir:{artefact}" if os.path.exists(artefact) else artefact
        result = self.run([binary, reference, "-o", "json", "-q"])
        if result is None:
            return []

        data = self.parse_json(result.stdout)
        if not data:
            return []

        findings: list[ScanVulnerability] = []

        for match in data.get("matches", []) or []:
            vulnerability = match.get("vulnerability", {}) or {}
            artifact = match.get("artifact", {}) or {}

            severity = (vulnerability.get("severity") or "UNKNOWN").upper()
            cvss_score = self._best_cvss(vulnerability) or self.severity_to_cvss(severity)
            package_name = artifact.get("name", "unknown")
            package_version = artifact.get("version", "")
            fix_versions = (vulnerability.get("fix") or {}).get("versions") or []

            # A GHSA-primary match carries its CVE under relatedVulnerabilities;
            # reading only the primary id dropped the CVE for every npm advisory.
            candidate_ids = [vulnerability.get("id") or ""] + [
                (related or {}).get("id") or ""
                for related in match.get("relatedVulnerabilities", []) or []
            ]
            cve_id = next(
                (i.upper() for i in candidate_ids if i.upper().startswith("CVE-")), None
            )

            findings.append(ScanVulnerability(
                cve_id=cve_id,
                cvss_score=cvss_score,
                severity=self.parse_severity(cvss_score) if cvss_score else severity,
                description=(
                    f"{package_name} {package_version}: "
                    f"{vulnerability.get('description', vulnerability.get('id', ''))}"
                )[:1000],
                affected_host=artefact,
                affected_service=package_name,
                solution=(
                    f"Upgrade {package_name} to {', '.join(fix_versions)}."
                    if fix_versions
                    else f"No fix is currently published for {package_name}."
                ),
                references=(vulnerability.get("urls") or [])[:5],
                # Severity is not evidence of a public exploit; KEV enrichment
                # is what establishes exploitation, so do not assert it here.
                exploit_available=False,
                source_scanner=self.name,
                raw_output={
                    "type": "grype",
                    "package": package_name,
                    "version": package_version,
                    "vuln_id": vulnerability.get("id", ""),
                },
            ))

        logger.info("Grype reported %d findings for %s", len(findings), artefact)
        return findings

    @staticmethod
    def _best_cvss(vulnerability: dict) -> float:
        """Highest CVSS base score Grype reports for a match."""
        best = 0.0
        for entry in vulnerability.get("cvss", []) or []:
            metrics = entry.get("metrics", {}) or {}
            try:
                best = max(best, float(metrics.get("baseScore", 0) or 0))
            except (TypeError, ValueError):
                continue
        return best
