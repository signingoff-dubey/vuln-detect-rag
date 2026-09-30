"""Static inspection of untrusted files and links.

Nothing here executes, renders or opens the input. Files are read as bytes and
links are parsed as strings; the only network access is the opt-in redirect
trace, which re-validates every hop against the same SSRF rules as scan targets.

Both analyzers return the same shape: verdict, score, and a list of findings
with a severity, so the UI renders them identically.
"""
import hashlib
import io
import ipaddress
import re
import unicodedata
import zipfile
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

import httpx
from fastapi import HTTPException

from services.target_validation import validate_target

MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_ZIP_ENTRIES = 5000
MAX_ZIP_EXPANDED = 1024 * 1024 * 1024
MAX_REDIRECTS = 5

SEVERITY_POINTS = {"critical": 60, "high": 35, "medium": 15, "low": 5, "info": 0}


def _finding(severity: str, title: str, detail: str) -> dict:
    return {"severity": severity, "title": title, "detail": detail}


def _verdict(findings: list) -> dict:
    score = min(100, sum(SEVERITY_POINTS[f["severity"]] for f in findings))
    if score >= 60:
        verdict = "dangerous"
    elif score >= 15:
        verdict = "suspicious"
    else:
        verdict = "clean"
    return {"verdict": verdict, "score": score}


# --------------------------------------------------------------------- files

EXECUTABLE_EXT = {
    "exe", "dll", "scr", "com", "msi", "sys", "cpl", "bat", "cmd", "ps1", "psm1", "vbs", "vbe",
    "js", "jse", "wsf", "wsh", "hta", "jar", "lnk", "reg", "inf", "sh", "py", "pl", "rb",
    "apk", "app", "deb", "rpm", "iso", "img", "vhd", "vhdx", "chm", "url",
}
MACRO_EXT = {"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "sldm", "xlsb"}
DECOY_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "rtf", "csv", "zip"}
ARCHIVE_EXT = {"zip", "jar", "apk", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "odt", "ods", "odp"}

# (prefix bytes, kind, extensions that legitimately carry it)
MAGIC = [
    (b"MZ", "windows-executable", {"exe", "dll", "scr", "sys", "cpl", "com", "msi"}),
    (b"\x7fELF", "elf-executable", {"", "so", "bin", "elf", "o"}),
    (b"%PDF-", "pdf", {"pdf"}),
    (b"PK\x03\x04", "zip", ARCHIVE_EXT | {"odt", "ods", "odp"}),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole2", {"doc", "xls", "ppt", "msi", "msg", "dot", "xlt", "pps"}),
    (b"\x89PNG\r\n\x1a\n", "png", {"png"}),
    (b"\xff\xd8\xff", "jpeg", {"jpg", "jpeg", "jfif"}),
    (b"GIF87a", "gif", {"gif"}),
    (b"GIF89a", "gif", {"gif"}),
    (b"{\\rtf", "rtf", {"rtf"}),
    (b"Rar!\x1a\x07", "rar", {"rar"}),
    (b"7z\xbc\xaf\x27\x1c", "7z", {"7z"}),
    (b"\x1f\x8b", "gzip", {"gz", "tgz"}),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "windows-shortcut", {"lnk"}),
    (b"#!", "script", {"", "sh", "py", "pl", "rb"}),
]

PDF_RISKY = [
    (rb"/JavaScript|/JS\b", "high", "Embedded JavaScript"),
    (rb"/OpenAction|/AA\b", "medium", "Runs an action when opened"),
    (rb"/Launch\b", "critical", "Can launch an external program"),
    (rb"/EmbeddedFile", "medium", "Contains an embedded file"),
    (rb"/RichMedia|/Flash", "medium", "Embedded rich media"),
    (rb"/XFA\b", "low", "XFA form (large attack surface)"),
    (rb"/SubmitForm|/ImportData", "medium", "Can send or import form data"),
]

SCRIPT_PATTERNS = [
    (rb"(?i)powershell[^\n]{0,80}-e(nc|ncodedcommand)?\s", "high", "PowerShell encoded command"),
    (rb"(?i)FromBase64String", "medium", "Decodes base64 at runtime"),
    (rb"(?i)WScript\.Shell|Scripting\.FileSystemObject|ActiveXObject", "high", "Windows scripting host objects"),
    (rb"(?i)certutil[^\n]{0,60}-(urlcache|decode)", "high", "certutil used as a downloader/decoder"),
    (rb"(?i)Invoke-Expression|\biex\b\s*\(|DownloadString|DownloadFile|Net\.WebClient", "high", "Downloads and runs remote content"),
    (rb"(?i)\beval\s*\(|\bunescape\s*\(|String\.fromCharCode", "medium", "Obfuscated script primitives"),
    (rb"(?i)cmd(\.exe)?\s*/c\s", "medium", "Spawns a command shell"),
    (rb"(?i)(curl|wget)[^\n]{0,100}\|\s*(ba)?sh", "high", "Pipes a download into a shell"),
]

HTML_PATTERNS = [
    (rb"(?i)<script\b", "high", "Contains <script> element"),
    (rb"(?i)\bon(load|error|click|mouseover|focus)\s*=", "high", "Inline event handler"),
    (rb"(?i)javascript\s*:", "high", "javascript: URL"),
    (rb"(?i)<(iframe|object|embed)\b", "medium", "Embeds external content"),
    (rb"(?i)<meta[^>]+http-equiv=[\"']?refresh", "medium", "Automatic redirect"),
]

OLE_MACRO_MARKERS = [b"_VBA_PROJECT", b"VBA/", b"Macros/", b"AutoOpen", b"Auto_Open", b"Document_Open", b"Workbook_Open"]
OLE_ABUSE = [b"Shell(", b"CreateObject", b"URLDownloadToFile", b"Wscript.Shell", b"powershell"]


def _detect_kind(head: bytes):
    for prefix, kind, exts in MAGIC:
        if head.startswith(prefix):
            return kind, exts
    sample = head[:2048]
    if sample and b"\x00" not in sample:
        low = sample.lower()
        if b"<svg" in low:
            return "svg", {"svg"}
        if b"<html" in low or b"<!doctype html" in low:
            return "html", {"html", "htm"}
        return "text", None
    return "unknown", None


def _check_filename(name: str, findings: list) -> str:
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    if any(unicodedata.category(c) == "Cf" for c in base):
        findings.append(_finding(
            "critical", "Hidden direction-override character in filename",
            "Characters such as U+202E reverse how the name is displayed, a common trick to disguise an executable as a document.",
        ))
    parts = [p for p in base.strip().rstrip(". ").split(".") if p != ""]
    ext = parts[-1].lower() if len(parts) > 1 else ""
    if base != base.rstrip(". "):
        findings.append(_finding("medium", "Trailing dot or space in filename", "Windows silently drops these, hiding the real extension."))
    if len(parts) > 2 and parts[-2].lower() in DECOY_EXT and ext in EXECUTABLE_EXT:
        findings.append(_finding(
            "critical", "Double extension",
            "Named like a .%s but actually ends in .%s." % (parts[-2].lower(), ext),
        ))
    if ext in EXECUTABLE_EXT:
        findings.append(_finding("high", "Executable or script file type", "Files ending in .%s can run code when opened." % ext))
    elif ext in MACRO_EXT:
        findings.append(_finding("high", "Macro-enabled Office format", "The .%s format is designed to carry VBA macros." % ext))
    return ext


def _scan_patterns(data: bytes, patterns: list, findings: list) -> None:
    for pattern, severity, label in patterns:
        if re.search(pattern, data):
            findings.append(_finding(severity, label, "Matched in file contents."))


def _analyze_zip(data: bytes, ext: str, findings: list) -> dict:
    info = {}
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        findings.append(_finding("medium", "Corrupt archive", "Starts like a ZIP but cannot be parsed, which is sometimes used to evade scanners."))
        return info
    entries = zf.infolist()
    info["entries"] = len(entries)
    if len(entries) > MAX_ZIP_ENTRIES:
        findings.append(_finding("high", "Excessive entry count", "%d entries; possible archive bomb." % len(entries)))
        return info
    expanded = sum(e.file_size for e in entries)
    compressed = sum(e.compress_size for e in entries) or 1
    info["expanded_bytes"] = expanded
    if expanded > MAX_ZIP_EXPANDED or (expanded > 50 * 1024 * 1024 and expanded / compressed > 100):
        findings.append(_finding("critical", "Archive bomb", "Expands to %.0f MB at a %dx ratio." % (expanded / 1048576, expanded // compressed)))
    names = [e.filename for e in entries]
    if any(n.startswith(("/", "\\")) or ".." in n.replace("\\", "/").split("/") for n in names):
        findings.append(_finding("critical", "Path traversal in entry names", "Extracting would write outside the target folder (zip-slip)."))
    if any(e.flag_bits & 0x1 for e in entries):
        findings.append(_finding("medium", "Encrypted entries", "Contents cannot be inspected, and password-protected archives are a common malware carrier."))
    inner_exec = sorted({n for n in names if n.rsplit(".", 1)[-1].lower() in EXECUTABLE_EXT and "." in n})
    is_office = ext in {"docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "dotm", "xltm"}
    if inner_exec and not is_office:
        findings.append(_finding("high", "Archive contains executables", ", ".join(inner_exec[:6])))
    if any(n.rsplit(".", 1)[-1].lower() in {"zip", "rar", "7z", "gz"} for n in names if "." in n):
        findings.append(_finding("low", "Nested archives", "Archives inside archives hinder inspection."))
    lowered = [n.lower() for n in names]
    if any(n.endswith("vbaproject.bin") for n in lowered):
        findings.append(_finding("high", "Contains VBA macros", "vbaProject.bin is present."))
    if any("/embeddings/" in n or "activex" in n for n in lowered):
        findings.append(_finding("medium", "Embedded OLE or ActiveX objects", "Office documents can hide payloads in embedded objects."))
    if is_office:
        for n in names:
            if n.endswith(".rels"):
                try:
                    rels = zf.read(n)[:2_000_000]
                except Exception:
                    continue
                if re.search(rb'TargetMode="External"[^>]*(oleObject|attachedTemplate|frame)|(oleObject|attachedTemplate|frame)[^>]*TargetMode="External"', rels):
                    findings.append(_finding("high", "Loads remote content", "Relationship in %s points to an external template or object (template injection)." % n))
                    break
    return info


def analyze_file(filename: str, data: bytes) -> dict:
    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(status_code=413, detail="File too large (limit %d MB)" % (MAX_FILE_BYTES // 1048576))
    if not data:
        raise HTTPException(status_code=400, detail="File is empty")

    findings: list = []
    ext = _check_filename(filename or "", findings)
    kind, legit = _detect_kind(data[:4096])

    if legit is not None and ext not in legit and kind not in {"text", "unknown"}:
        severity = "high" if kind in {"windows-executable", "elf-executable", "windows-shortcut"} else "medium"
        findings.append(_finding(
            severity, "Content does not match extension",
            "Extension is .%s but the bytes identify as %s." % (ext or "(none)", kind),
        ))

    details: dict = {}
    if kind == "windows-executable":
        findings.append(_finding("high", "Windows executable", "Contains a PE program."))
    elif kind == "elf-executable":
        findings.append(_finding("high", "Linux executable", "Contains an ELF program."))
    elif kind == "windows-shortcut":
        findings.append(_finding("high", "Windows shortcut", "LNK files can run arbitrary commands."))
    elif kind == "pdf":
        _scan_patterns(data, [(re.compile(p), s, l) for p, s, l in PDF_RISKY], findings)
    elif kind == "zip":
        details = _analyze_zip(data, ext, findings)
    elif kind == "ole2":
        if any(m in data for m in OLE_MACRO_MARKERS):
            findings.append(_finding("high", "Contains VBA macros", "Legacy Office file with a macro project."))
            if any(m.lower() in data.lower() for m in OLE_ABUSE):
                findings.append(_finding("high", "Macro calls system or download functions", "Shell/CreateObject/download calls found alongside the macro."))
    elif kind in {"html", "svg"}:
        _scan_patterns(data, HTML_PATTERNS, findings)
    elif kind in {"text", "script"}:
        _scan_patterns(data, SCRIPT_PATTERNS, findings)
    elif kind == "rtf" and re.search(rb"\\objdata|\\objemb", data):
        findings.append(_finding("high", "Embedded object in RTF", "RTF object streams are a frequent exploit vector."))

    if kind in {"png", "jpeg", "gif"} and ext in {"png", "jpg", "jpeg", "gif"}:
        tail = data[-65536:]
        if b"<?php" in tail or b"<script" in tail.lower() or b"MZ\x90\x00" in tail:
            findings.append(_finding("high", "Payload appended to image", "Executable or script content follows the image data."))

    if not findings:
        findings.append(_finding("info", "No risky indicators found", "Static checks passed. This does not prove the file is safe."))

    result = {
        "filename": filename,
        "size": len(data),
        "detected_type": kind,
        "extension": ext,
        "hashes": {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        "details": details,
        "findings": findings,
    }
    result.update(_verdict(findings))
    return result


# --------------------------------------------------------------------- links

TRACKING_PARAMS = {
    "fbclid", "gclid", "gclsrc", "dclid", "msclkid", "yclid", "mc_eid", "mc_cid", "igshid", "_hsenc", "_hsmi",
    "mkt_tok", "oly_enc_id", "oly_anon_id", "vero_id", "wickedid", "ref_src", "ref_url", "spm", "s_cid",
}
TRACKING_PREFIXES = ("utm_", "pk_", "hsa_", "trk_")
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
    "shorturl.at", "tiny.cc", "rb.gy", "lnkd.in", "t.ly", "s.id",
}
RISKY_TLDS = {"zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf", "ga", "work", "support", "rest", "icu", "cyou"}
BRANDS = {"paypal", "microsoft", "google", "apple", "amazon", "netflix", "facebook", "instagram", "office365", "outlook", "binance", "coinbase"}
DANGEROUS_SCHEMES = {"javascript", "data", "vbscript", "file", "blob"}


def defang(url: str) -> str:
    return url.replace("http", "hxxp", 1).replace(".", "[.]").replace("://", "[://]", 1) if url else url


def _strip_tracking(parts):
    kept = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
            if k.lower() not in TRACKING_PARAMS and not k.lower().startswith(TRACKING_PREFIXES)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(kept), "")), len(parse_qsl(parts.query, keep_blank_values=True)) - len(kept)


def _host_findings(host: str, findings: list) -> None:
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        findings.append(_finding("medium", "Raw IP address instead of a domain name", "Legitimate services rarely link by IP."))
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            findings.append(_finding("high", "Points at an internal address", "Opening this from a server can reach private services (SSRF)."))
        return
    except ValueError:
        pass
    if re.fullmatch(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}", host, re.I):
        findings.append(_finding("high", "Obfuscated numeric host", "Decimal, hex or octal notation is used to disguise an IP address."))
    if "xn--" in host:
        try:
            shown = host.encode("ascii").decode("idna")
        except UnicodeError:
            shown = "(malformed punycode)"
        findings.append(_finding("high", "Punycode (internationalised) domain", "May imitate a known site with look-alike characters: %s" % shown))
    elif any(ord(c) > 127 for c in host):
        findings.append(_finding("high", "Non-ASCII characters in domain", "Look-alike characters can imitate a trusted site."))
    labels = host.split(".")
    if labels[-1].lower() in RISKY_TLDS:
        findings.append(_finding("low", "Top-level domain often abused", ".%s sees disproportionate phishing and malware use." % labels[-1].lower()))
    if len(labels) > 4:
        findings.append(_finding("low", "Unusually deep subdomain nesting", "Long subdomain chains often bury the real domain."))
    registrable = ".".join(labels[-2:]) if len(labels) >= 2 else host
    for brand in BRANDS:
        if brand in host.lower() and brand not in registrable.lower().split(".")[0]:
            findings.append(_finding("high", "Brand name in subdomain of another domain", "%s appears in the host but the real domain is %s." % (brand, registrable)))
            break
    if host.lower() in SHORTENERS:
        findings.append(_finding("medium", "URL shortener", "The final destination is hidden; trace redirects to see it."))


def analyze_link(raw: str, trace: bool = False) -> dict:
    raw = (raw or "").strip()
    if not raw or len(raw) > 4096:
        raise HTTPException(status_code=400, detail="Link is required (max 4096 characters)")
    if re.search(r"[\x00-\x1f\x7f]", raw):
        raise HTTPException(status_code=400, detail="Link contains control characters")

    findings: list = []
    candidate = raw if re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:", raw) else "http://" + raw
    parts = urlsplit(candidate)
    scheme = parts.scheme.lower()

    if scheme in DANGEROUS_SCHEMES:
        findings.append(_finding("critical", "Dangerous URL scheme", "%s: links run code or expose local content and must not be opened." % scheme))
        result = {"input": raw, "defanged": defang(raw), "clean_url": None, "host": "", "redirects": [], "findings": findings}
        result.update(_verdict(findings))
        return result
    if scheme not in {"http", "https"}:
        findings.append(_finding("medium", "Unusual URL scheme", "%s: hands the link to another application." % scheme))
    elif scheme == "http":
        findings.append(_finding("low", "Unencrypted HTTP", "Traffic can be read or altered in transit."))

    host = (parts.hostname or "").lower()
    if not host:
        raise HTTPException(status_code=400, detail="Link has no host")
    if parts.username is not None or "@" in parts.netloc:
        findings.append(_finding("high", "Credentials or '@' in the address", "Text before '@' is ignored by the browser, so the visible name is not the real destination."))
    try:
        port = parts.port
    except ValueError:
        raise HTTPException(status_code=400, detail="Link has an invalid port")
    if port and port not in {80, 443}:
        findings.append(_finding("low", "Non-standard port", "Port %d." % port))
    _host_findings(host, findings)

    decoded = unquote(unquote(parts.path + "?" + parts.query))
    if decoded != unquote(parts.path + "?" + parts.query):
        findings.append(_finding("low", "Double-encoded characters", "Repeated percent-encoding can hide content from filters."))
    if re.search(r"(?i)<script|javascript:|onerror\s*=", decoded):
        findings.append(_finding("high", "Script content in the URL", "Looks like a cross-site scripting payload."))
    if re.search(r"(?i)(?:^|[?&=/])(https?%3a|https?://)", parts.path + "?" + parts.query) and parts.query:
        findings.append(_finding("low", "Another URL embedded in the parameters", "Possible open redirect."))
    if re.search(r"(?i)\.(exe|scr|msi|bat|cmd|ps1|vbs|js|jar|apk|iso|lnk|hta)(?:$|\?)", parts.path):
        findings.append(_finding("high", "Link downloads an executable", "The path ends in a program or script."))

    clean, removed = _strip_tracking(parts)
    if removed:
        findings.append(_finding("info", "Tracking parameters removed", "%d parameter(s) stripped from the clean link." % removed))
    if parts.fragment:
        findings.append(_finding("info", "Fragment removed", "The #fragment is never sent to the server."))

    redirects: list = []
    if trace and scheme in {"http", "https"}:
        redirects = _trace_redirects(clean, findings)

    if not any(f["severity"] != "info" for f in findings):
        findings.append(_finding("info", "No risky indicators found", "Static checks passed. This does not prove the site is safe."))

    result = {
        "input": raw,
        "defanged": defang(clean),
        "clean_url": clean,
        "host": host,
        "redirects": redirects,
        "findings": findings,
    }
    result.update(_verdict(findings))
    return result


def _trace_redirects(url: str, findings: list) -> list:
    """Follow redirects by hand so each hop is validated before it is contacted.

    Only headers are read (HEAD, body never downloaded), and any hop that
    resolves to a private or reserved address stops the trace.
    """
    hops = []
    current = url
    with httpx.Client(follow_redirects=False, timeout=6.0, headers={"User-Agent": "VulnDetect-LinkCheck/1.0"}) as client:
        for _ in range(MAX_REDIRECTS + 1):
            host = urlsplit(current).hostname or ""
            try:
                validate_target(host, resolve=True)
            except HTTPException as exc:
                hops.append({"url": current, "status": None, "note": "Not contacted: %s" % exc.detail})
                findings.append(_finding("high", "Redirect leads to a blocked address", exc.detail))
                return hops
            try:
                resp = client.head(current)
                if resp.status_code in {405, 501}:
                    resp = client.get(current, headers={"Range": "bytes=0-0"})
            except httpx.HTTPError as exc:
                hops.append({"url": current, "status": None, "note": type(exc).__name__})
                findings.append(_finding("low", "Link could not be reached", type(exc).__name__))
                return hops
            hops.append({"url": current, "status": resp.status_code, "note": ""})
            location = resp.headers.get("location")
            if resp.status_code in {301, 302, 303, 307, 308} and location:
                current = str(httpx.URL(current).join(location))
                if urlsplit(current).scheme not in {"http", "https"}:
                    findings.append(_finding("critical", "Redirects to a dangerous scheme", current[:100]))
                    return hops
                continue
            break
        else:
            findings.append(_finding("medium", "Too many redirects", "More than %d hops." % MAX_REDIRECTS))
    if len(hops) > 1:
        first, last = urlsplit(hops[0]["url"]).hostname, urlsplit(hops[-1]["url"]).hostname
        findings.append(_finding("medium" if first != last else "info", "Link redirects %d time(s)" % (len(hops) - 1), "Final destination: %s" % hops[-1]["url"]))
    return hops
