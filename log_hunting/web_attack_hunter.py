#!/usr/bin/env python3
"""웹 서버 접근 로그(Apache/Nginx combined·common)에서 공격 패턴을 찾는다.

URL은 두 번까지 URL 디코딩한 뒤 검사하며, User-Agent·Referer 도 함께 본다.
탐지 범주: SQLi, XSS, LFI/Path Traversal, RCE/Command Injection, Log4Shell(JNDI),
          SSTI, WebShell, Sensitive File 탐색, Scanner UA
응답 코드가 2xx 인 공격 요청은 '성공 가능성'이 있으므로 status 컬럼을 꼭 확인할 것.
종료 코드: 0=탐지 없음, 1=오류, 2=탐지 있음

예시:
  web_attack_hunter.py /var/log/nginx/access.log*
  web_attack_hunter.py access.log --summary            # IP별 요약
  web_attack_hunter.py access.log --category sqli,rce --success-only
"""
import argparse
import re
import sys
import urllib.parse
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib.cli import EXIT_DETECTED, EXIT_OK, add_output_args, check_files_exist, die, iter_lines, setup_stdio, warn  # noqa: E402
from lib.output import emit  # noqa: E402

LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+|-) ?(?P<path>[^"]*?)(?: (?P<proto>HTTP/[\d.]+))?" '
    r'(?P<status>\d{3}|-) (?P<size>\S+)'
    r'(?: "(?P<referer>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?'
)

# (category, rule name, regex) — 요청 URL(디코딩)에 적용
URL_RULES: List[Tuple[str, str, str]] = [
    ("sqli", "union-select", r"union(?:\s|/\*.*?\*/|\+)+(?:all(?:\s|\+)+)?select"),
    ("sqli", "boolean-tautology", r"['\"]\s*(?:or|and)\s*['\"]?\w*['\"]?\s*=\s*['\"]?\w*|\bor\s+1\s*=\s*1\b"),
    ("sqli", "time-based", r"\b(?:sleep|benchmark|pg_sleep|dbms_pipe\.receive_message)\s*\(|waitfor\s+delay\s"),
    ("sqli", "schema-enum", r"information_schema|sys\.tables|sqlite_master|@@version"),
    ("sqli", "comment-terminator", r"'\s*(?:--|#|/\*)"),
    ("xss", "script-tag", r"<\s*script\b|<\s*/\s*script\s*>"),
    ("xss", "event-handler", r"\bon(?:error|load|mouseover|focus|click)\s*="),
    ("xss", "js-uri", r"javascript\s*:|document\.cookie|alert\s*\(|<\s*(?:img|svg|iframe)\b"),
    ("lfi", "path-traversal", r"(?:\.\./|\.\.\\){2,}|%2e%2e[/\\]"),
    ("lfi", "sensitive-os-file", r"/etc/(?:passwd|shadow|hosts|issue)|boot\.ini|win\.ini|/proc/self/"),
    ("lfi", "php-wrapper", r"\b(?:php|file|zip|phar|data|expect)://"),
    ("rce", "shell-metachar", r"[;|`]\s*(?:cat|id|whoami|uname|ls|wget|curl|nc|bash|sh|ping)\b|\$\((?:[^)]*)\)"),
    ("rce", "shell-binary", r"/bin/(?:ba)?sh\b|cmd\.exe|powershell(?:\.exe)?\b"),
    ("rce", "download-exec", r"\b(?:wget|curl)\s+https?://"),
    ("log4shell", "jndi-lookup", r"\$\{(?:jndi|\$\{[^}]*\}j|lower:j|::-j)"),
    ("ssti", "template-expr", r"\{\{\s*\d+\s*\*\s*\d+\s*\}\}|\$\{\d+\*\d+\}|\{\{.*?(?:config|self|__class__).*?\}\}"),
    ("webshell", "webshell-access", r"/(?:shell|cmd|c99|r57|wso|b374k|alfa)\w*\.(?:php|asp|aspx|jsp)|[?&](?:cmd|exec|command)="),
    ("recon", "sensitive-file", r"/\.env\b|/\.git/|/\.svn/|/\.htpasswd|wp-config\.php|/server-status|/phpinfo\.php|\.(?:bak|old|swp|sql)(?:$|\?)"),
]

UA_RULES: List[Tuple[str, str, str]] = [
    ("scanner", "scanner-ua", r"sqlmap|nikto|nmap|masscan|zgrab|nuclei|dirbuster|gobuster|feroxbuster|wpscan|acunetix|nessus|openvas|wfuzz|ffuf|hydra|whatweb"),
    ("log4shell", "jndi-in-header", r"\$\{(?:jndi|\$\{[^}]*\}j|lower:j|::-j)"),
    ("xss", "xss-in-header", r"<\s*script\b"),
    ("rce", "shellshock", r"\(\)\s*\{\s*:\s*;\s*\}"),
]

COMPILED_URL = [(c, n, re.compile(p, re.IGNORECASE)) for c, n, p in URL_RULES]
COMPILED_UA = [(c, n, re.compile(p, re.IGNORECASE)) for c, n, p in UA_RULES]
CATEGORIES = sorted({c for c, _, _ in URL_RULES + UA_RULES})


def decode(value: str) -> str:
    for _ in range(2):
        new = urllib.parse.unquote_plus(value)
        if new == value:
            break
        value = new
    return value


def inspect(entry: Dict[str, str]) -> List[Tuple[str, str]]:
    hits = []
    target = decode(entry.get("path") or "")
    for cat, name, rx in COMPILED_URL:
        if rx.search(target):
            hits.append((cat, name))
    headers = f"{entry.get('ua') or ''} {entry.get('referer') or ''}"
    for cat, name, rx in COMPILED_UA:
        if rx.search(headers):
            hits.append((cat, name))
    return hits


def parse_line(line: str) -> Optional[Dict[str, str]]:
    m = LOG_RE.match(line)
    return m.groupdict() if m else None


def main() -> int:
    setup_stdio()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="*", help="access 로그 (생략 시 stdin, .gz 지원)")
    ap.add_argument("-c", "--category", help=f"특정 범주만 (쉼표 구분): {','.join(CATEGORIES)}")
    ap.add_argument("-s", "--summary", action="store_true", help="IP별 요약만 출력")
    ap.add_argument("--success-only", action="store_true", help="2xx/3xx 응답만 (공격 성공 가능성)")
    ap.add_argument("--min-hits", type=int, default=1, help="요약 시 최소 탐지 건수 (기본 1)")
    add_output_args(ap)
    args = ap.parse_args()
    check_files_exist(args.files)

    cats = None
    if args.category:
        cats = {c.strip().lower() for c in args.category.split(",")}
        if cats - set(CATEGORIES):
            die(f"알 수 없는 범주: {', '.join(cats - set(CATEGORIES))}")

    findings: List[Dict[str, Any]] = []
    unparsed = 0
    for line in iter_lines(args.files):
        if not line.strip():
            continue
        entry = parse_line(line)
        if not entry:
            unparsed += 1
            continue
        hits = [h for h in inspect(entry) if cats is None or h[0] in cats]
        if not hits:
            continue
        status = entry["status"]
        if args.success_only and not status.startswith(("2", "3")):
            continue
        findings.append({
            "time": entry["time"], "ip": entry["ip"], "method": entry["method"],
            "status": status, "categories": sorted({c for c, _ in hits}),
            "rules": sorted({n for _, n in hits}), "path": entry["path"],
            "ua": entry.get("ua") or "",
        })

    if unparsed:
        warn(f"형식을 인식하지 못한 줄 {unparsed}개 (combined/common 로그 형식만 지원)")

    if args.summary:
        per_ip: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"hits": 0, "cats": Counter(), "ok": 0,
                                                                 "first": None, "last": None})
        for f in findings:
            s = per_ip[f["ip"]]
            s["hits"] += 1
            s["cats"].update(f["categories"])
            s["ok"] += f["status"].startswith("2")
            s["first"] = s["first"] or f["time"]
            s["last"] = f["time"]
        rows = [{"ip": ip, "hits": s["hits"], "success_2xx": s["ok"],
                 "categories": [f"{c}:{n}" for c, n in s["cats"].most_common()],
                 "first_seen": s["first"], "last_seen": s["last"]}
                for ip, s in per_ip.items() if s["hits"] >= args.min_hits]
        rows.sort(key=lambda r: -r["hits"])
        emit(rows, args.fmt, title="Web Attack Summary by IP")
    else:
        emit(findings, args.fmt, columns=["time", "ip", "method", "status", "categories", "rules", "path", "ua"],
             title="Web Attack Findings")

    return EXIT_DETECTED if findings else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
