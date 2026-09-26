#!/usr/bin/env python3
"""의심 메일(.eml) 분석기 — 헤더 경로, 인증 결과, 발신자 위장, URL, 첨부파일.

확인 항목:
  - Received 체인 (전달 경로, 경유 IP) — 아래에서 위로 읽음(최초 발신 → 최종 수신)
  - SPF / DKIM / DMARC 결과 (Authentication-Results, Received-SPF)
  - From / Reply-To / Return-Path 도메인 불일치, 표시 이름에 다른 주소 삽입
  - 본문 URL 추출, HTML 링크 텍스트와 실제 href 도메인 불일치
  - 첨부파일 해시(MD5/SHA256), 위험 확장자, 이중 확장자
종료 코드: 0=의심 요소 없음, 1=오류, 2=의심 요소 있음

예시:
  eml_analyzer.py suspicious.eml
  eml_analyzer.py suspicious.eml --json > report.json
  eml_analyzer.py suspicious.eml --extract-attachments ./quarantine
"""
import argparse
import email
import hashlib
import re
import sys
from email import policy
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib.cli import EXIT_DETECTED, EXIT_OK, check_files_exist, setup_stdio, warn  # noqa: E402
from lib.ioc_patterns import URL_RE, is_internal_ip  # noqa: E402
from lib.output import emit, emit_sections  # noqa: E402

DANGEROUS_EXT = {
    "exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "hta", "lnk",
    "ps1", "msi", "jar", "cpl", "iso", "img", "vhd", "vhdx", "one", "docm", "xlsm", "pptm",
    "xlam", "html", "htm", "svg", "chm", "reg", "dll", "zip", "rar", "7z", "ace", "gz",
}
BENIGN_DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "png", "rtf"}
IP_RE = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3})\]?")


class LinkParser(HTMLParser):
    """<a href> 와 링크 텍스트 수집."""

    def __init__(self) -> None:
        super().__init__()
        self.links: List[Tuple[str, str]] = []
        self._href: Optional[str] = None
        self._text: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip(">") if "@" in addr else ""


def url_host(url: str) -> str:
    m = re.match(r"^[a-z][a-z0-9+.-]*://([^/:?#]+)", url.strip(), re.I)
    return m.group(1).lower() if m else ""


def base_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "or", "ne", "go", "ac", "org", "net"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def parse_received(values: List[str]) -> List[Dict[str, Any]]:
    hops = []
    for i, raw in enumerate(reversed(values), 1):  # 가장 오래된 홉부터
        raw = " ".join(raw.split())
        frm = re.search(r"\bfrom\s+(.+?)(?=\s+by\s|\s*;|$)", raw)
        by = re.search(r"\bby\s+(\S+)", raw)
        date = raw.rsplit(";", 1)[-1].strip() if ";" in raw else ""
        ips = [ip for ip in IP_RE.findall(frm.group(1) if frm else "")]
        hops.append({
            "hop": i,
            "from": frm.group(1)[:80] if frm else "",
            "by": by.group(1) if by else "",
            "ips": ips,
            "external_ips": [ip for ip in ips if not is_internal_ip(ip)],
            "date": date,
        })
    return hops


def parse_auth(msg: EmailMessage) -> Dict[str, str]:
    result = {"spf": "none", "dkim": "none", "dmarc": "none"}
    text = " ".join(str(v) for v in msg.get_all("Authentication-Results", []) or [])
    for key in result:
        m = re.search(rf"\b{key}\s*=\s*(\w+)", text, re.I)
        if m:
            result[key] = m.group(1).lower()
    if result["spf"] == "none":
        rspf = msg.get("Received-SPF")
        if rspf:
            result["spf"] = str(rspf).split()[0].lower()
    return result


def body_parts(msg: EmailMessage) -> Tuple[str, str]:
    plain, html = [], []
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeDecodeError):
            content = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
        (html if ctype == "text/html" else plain).append(content)
    return "\n".join(plain), "\n".join(html)


def analyze(path: Path, extract_dir: Optional[Path] = None) -> Dict[str, Any]:
    with path.open("rb") as fh:
        msg: EmailMessage = email.message_from_binary_file(fh, policy=policy.default)  # type: ignore[assignment]

    flags: List[Dict[str, str]] = []

    def flag(severity: str, rule: str, detail: str) -> None:
        flags.append({"severity": severity, "rule": rule, "detail": detail})

    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    reply_to = [a for _, a in getaddresses([str(v) for v in msg.get_all("Reply-To", []) or []])]
    return_path = parseaddr(str(msg.get("Return-Path", "")))[1]
    from_dom = domain_of(from_addr)

    summary = {
        "from": str(msg.get("From", "")), "reply_to": ", ".join(reply_to),
        "return_path": return_path, "to": str(msg.get("To", "")),
        "subject": str(msg.get("Subject", "")), "date": str(msg.get("Date", "")),
        "message_id": str(msg.get("Message-ID", "")),
    }

    # 발신자 위장
    embedded = re.search(r"[\w.+-]+@[\w.-]+\.\w+", from_name or "")
    if embedded and domain_of(embedded.group(0)) != from_dom:
        flag("high", "display-name-spoof", f"표시 이름에 {embedded.group(0)} 삽입, 실제 발신 {from_addr}")
    for rt in reply_to:
        if domain_of(rt) and base_domain(domain_of(rt)) != base_domain(from_dom):
            flag("medium", "reply-to-mismatch", f"Reply-To {rt} ≠ From 도메인 {from_dom}")
    if return_path and base_domain(domain_of(return_path)) != base_domain(from_dom):
        flag("low", "return-path-mismatch", f"Return-Path {return_path} ≠ From 도메인 {from_dom}")

    # 인증
    auth = parse_auth(msg)
    for key, value in auth.items():
        if value in ("fail", "softfail", "permerror"):
            flag("high" if key == "dmarc" or value == "fail" else "medium", f"{key}-{value}", f"{key.upper()} = {value}")
        elif value in ("none", "neutral", "temperror"):
            flag("low", f"{key}-{value}", f"{key.upper()} = {value}")

    hops = parse_received([str(v) for v in msg.get_all("Received", []) or []])
    origin_ip = next((h["external_ips"][0] for h in hops if h["external_ips"]), "")

    # URL
    plain, html = body_parts(msg)
    urls: Dict[str, Dict[str, Any]] = {}
    for u in URL_RE.findall(plain + "\n" + html):
        u = u.rstrip(".,;:!?'\")")
        urls.setdefault(u, {"url": u, "host": url_host(u), "link_text": "", "mismatch": False})
    lp = LinkParser()
    lp.feed(html)
    for href, text in lp.links:
        if not href or not re.match(r"^(?:https?|ftp)://", href, re.I):
            continue
        entry = urls.setdefault(href, {"url": href, "host": url_host(href), "link_text": "", "mismatch": False})
        entry["link_text"] = text[:60]
        shown = url_host(text) or (text.lower() if re.fullmatch(r"[\w.-]+\.[a-z]{2,}", text, re.I) else "")
        if shown and base_domain(shown) != base_domain(entry["host"]):
            entry["mismatch"] = True
            flag("high", "link-text-mismatch", f"보이는 링크 {text} → 실제 {entry['host']}")
    for u in urls.values():
        if re.fullmatch(r"[\d.]+", u["host"]):
            flag("medium", "ip-url", f"IP 주소 URL: {u['url']}")

    # 첨부파일
    attachments = []
    for part in msg.walk():
        filename = part.get_filename()
        if part.is_multipart() or (part.get_content_disposition() != "attachment" and not filename):
            continue
        data = part.get_payload(decode=True) or b""
        name = filename or "(no name)"
        exts = [e.lower() for e in name.split(".")[1:]]
        sha256 = hashlib.sha256(data).hexdigest()
        attachments.append({
            "filename": name, "content_type": part.get_content_type(), "size": len(data),
            "md5": hashlib.md5(data).hexdigest(), "sha256": sha256,
        })
        if exts and exts[-1] in DANGEROUS_EXT:
            flag("high", "dangerous-attachment", f"위험 확장자 첨부: {name}")
        if len(exts) >= 2 and exts[-2] in BENIGN_DOC_EXT and exts[-1] in DANGEROUS_EXT:
            flag("critical", "double-extension", f"이중 확장자 위장: {name}")
        if extract_dir:
            extract_dir.mkdir(parents=True, exist_ok=True)
            safe = re.sub(r"[^\w.-]", "_", name)
            # 실수로 실행되지 않도록 확장자를 .quarantine 으로 붙인다
            (extract_dir / f"{sha256[:16]}_{safe}.quarantine").write_bytes(data)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    flags.sort(key=lambda f: order[f["severity"]])
    return {"file": str(path), "summary": summary, "authentication": auth, "origin_ip": origin_ip,
            "received_hops": hops, "urls": list(urls.values()), "attachments": attachments, "flags": flags}


def main() -> int:
    setup_stdio()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+", help=".eml 파일")
    ap.add_argument("--json", action="store_true", help="JSON으로 출력")
    ap.add_argument("-x", "--extract-attachments", metavar="DIR", help="첨부파일을 DIR에 .quarantine 확장자로 저장")
    args = ap.parse_args()
    check_files_exist(args.files)

    reports = [analyze(Path(f), Path(args.extract_attachments) if args.extract_attachments else None)
               for f in args.files]

    if args.json:
        import json
        json.dump(reports if len(reports) > 1 else reports[0], sys.stdout, ensure_ascii=False, indent=2)
        print()
    else:
        for r in reports:
            print(f"\n##### {r['file']}")
            emit([{"field": k, "value": v} for k, v in r["summary"].items()], title="Summary", max_width=120)
            emit([{"check": k.upper(), "result": v} for k, v in r["authentication"].items()],
                 title="Authentication")
            emit(r["received_hops"], columns=["hop", "from", "by", "external_ips", "date"],
                 title=f"Received Hops (최초 발신 추정 IP: {r['origin_ip'] or '-'})")
            emit(r["urls"], columns=["host", "mismatch", "link_text", "url"], title="URLs", max_width=100)
            emit(r["attachments"], title="Attachments")
            emit_sections({"Flags": r["flags"]})

    if args.extract_attachments:
        warn(f"첨부파일 저장 위치: {args.extract_attachments} (실행 금지, 샌드박스에서만 분석)")
    return EXIT_DETECTED if any(r["flags"] for r in reports) else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
