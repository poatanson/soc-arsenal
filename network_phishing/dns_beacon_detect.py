#!/usr/bin/env python3
"""DNS 로그에서 C2 비커닝 · DGA · DNS 터널링 의심 활동 탐지.

입력 형식 (자동 판별):
  - Zeek dns.log (TSV, #fields 헤더)
  - Zeek dns.log JSON (한 줄에 JSON 하나)
  - dnsmasq / Pi-hole    "Sep 26 08:00:01 dnsmasq[123]: query[A] evil.com from 10.0.0.5"
  - 일반 텍스트          "<timestamp> <client> <query> [qtype]"  (ISO 8601 또는 epoch)

탐지:
  BEACON    (client, 도메인)별 질의 간격의 변동계수(CV = 표준편차/평균)가 낮음 → 기계적 주기성
  DGA       2차 레이블의 엔트로피·길이·자음/숫자 비율 기반 점수
  TUNNELING 긴 서브도메인 + 동일 상위 도메인 아래 고유 서브도메인 다수
종료 코드: 0=탐지 없음, 1=오류, 2=탐지 있음

예시:
  dns_beacon_detect.py /opt/zeek/logs/current/dns.log
  dns_beacon_detect.py dns.log --min-count 20 --max-cv 0.1 --allowlist allow.txt
"""
import argparse
import json
import math
import re
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib.cli import EXIT_DETECTED, EXIT_OK, add_output_args, check_files_exist, iter_lines, setup_stdio, warn  # noqa: E402
from lib.output import emit_sections  # noqa: E402

MULTI_TLDS = {"co.kr", "or.kr", "ne.kr", "go.kr", "ac.kr", "co.uk", "org.uk", "ac.uk", "com.au", "co.jp",
              "com.cn", "com.br", "co.in"}
# 흔한 CDN/클라우드/OS 텔레메트리 — 주기성이 정상이라 오탐이 많은 도메인
DEFAULT_ALLOW = {
    "google.com", "googleapis.com", "gstatic.com", "microsoft.com", "windows.com", "windowsupdate.com",
    "office.com", "office365.com", "live.com", "msftncsi.com", "apple.com", "icloud.com", "amazonaws.com",
    "akamaiedge.net", "akamai.net", "cloudflare.com", "cloudfront.net", "azure.com", "github.com",
    "ubuntu.com", "in-addr.arpa", "ip6.arpa", "local", "localdomain", "lan",
}
SYSLOG_TS = re.compile(r"^(\w{3})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2})")
DNSMASQ_RE = re.compile(r"query\[(\w+)\] (\S+) from (\S+)")
MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}


def parse_ts(value: str) -> Optional[float]:
    try:
        return float(value)
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def iter_queries(lines: Iterator[str]) -> Iterator[Tuple[float, str, str, str]]:
    """(ts, client, query, qtype)"""
    zeek_fields: Optional[List[str]] = None
    year = datetime.now().year
    for line in lines:
        if not line.strip():
            continue
        if line.startswith("#fields"):
            zeek_fields = line.split("\t")[1:]
            continue
        if line.startswith("#"):
            continue
        if zeek_fields:
            cols = dict(zip(zeek_fields, line.split("\t")))
            ts = parse_ts(cols.get("ts", ""))
            if ts is not None and cols.get("query", "-") != "-":
                yield ts, cols.get("id.orig_h", "?"), cols["query"], cols.get("qtype_name", "")
            continue
        if line.startswith("{"):
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            ts = parse_ts(str(obj.get("ts", "")))
            if ts is not None and obj.get("query"):
                yield ts, obj.get("id.orig_h", "?"), obj["query"], obj.get("qtype_name", "")
            continue
        m = DNSMASQ_RE.search(line)
        if m:
            sm = SYSLOG_TS.match(line)
            if sm and sm.group(1) in MONTHS:
                ts = datetime(year, MONTHS[sm.group(1)], int(sm.group(2)), int(sm.group(3)),
                              int(sm.group(4)), int(sm.group(5))).timestamp()
                yield ts, m.group(3), m.group(2), m.group(1)
            continue
        parts = line.replace(",", " ").split()
        if len(parts) >= 3:
            ts = parse_ts(parts[0])
            if ts is not None:
                yield ts, parts[1], parts[2], parts[3] if len(parts) > 3 else ""


def split_domain(q: str) -> Tuple[str, str, str]:
    """(서브도메인, 2차 레이블, 등록 도메인)"""
    parts = q.lower().rstrip(".").split(".")
    n = 3 if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_TLDS else 2
    if len(parts) < n:
        return "", parts[0], q.lower()
    return ".".join(parts[:-n]), parts[-n], ".".join(parts[-n:])


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def dga_score(label: str) -> float:
    """0~1. 긴 레이블, 높은 엔트로피, 모음 부족, 숫자 섞임, 긴 자음 연속일수록 높음."""
    if len(label) < 8:
        return 0.0
    ent = entropy(label)
    letters = [c for c in label if c.isalpha()]
    vowel_ratio = sum(c in "aeiou" for c in letters) / max(len(letters), 1)
    digit_ratio = sum(c.isdigit() for c in label) / len(label)
    max_consonant_run = max((len(r) for r in re.findall(r"[bcdfghjklmnpqrstvwxz]+", label)), default=0)
    score = 0.0
    score += min(max(ent - 2.8, 0) / 1.2, 1) * 0.40
    score += min(max(len(label) - 10, 0) / 10, 1) * 0.15
    score += (1 - min(vowel_ratio / 0.35, 1)) * 0.15
    score += min(digit_ratio / 0.3, 1) * 0.15 if 0 < digit_ratio < 1 else 0
    score += min(max(max_consonant_run - 3, 0) / 3, 1) * 0.15
    return round(score, 2)


def load_allowlist(path: Optional[str]) -> Set[str]:
    allow = set(DEFAULT_ALLOW)
    if path:
        allow |= {l.strip().lower() for l in Path(path).read_text(encoding="utf-8").splitlines()
                  if l.strip() and not l.startswith("#")}
    return allow


def allowed(domain: str, allow: Set[str]) -> bool:
    return any(domain == a or domain.endswith("." + a) for a in allow)


def main() -> int:
    setup_stdio()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="*", help="DNS 로그 (생략 시 stdin, .gz 지원)")
    ap.add_argument("--min-count", type=int, default=10, help="비커닝 판단 최소 질의 수 (기본 10)")
    ap.add_argument("--max-cv", type=float, default=0.2, help="비커닝 판정 최대 변동계수 (기본 0.2)")
    ap.add_argument("--min-interval", type=float, default=5.0, help="평균 간격 하한(초) - 버스트 제외 (기본 5)")
    ap.add_argument("--dga-threshold", type=float, default=0.6, help="DGA 점수 임계치 0~1 (기본 0.6)")
    ap.add_argument("--tunnel-len", type=int, default=50, help="터널링 의심 서브도메인 길이 (기본 50)")
    ap.add_argument("--tunnel-unique", type=int, default=20, help="터널링 판정 고유 서브도메인 수 (기본 20)")
    ap.add_argument("--allowlist", help="추가 허용 도메인 목록 파일 (한 줄에 하나)")
    add_output_args(ap)
    args = ap.parse_args()
    check_files_exist(args.files)
    allow = load_allowlist(args.allowlist)

    pair_times: Dict[Tuple[str, str], List[float]] = defaultdict(list)
    dga: Dict[str, Dict] = {}
    subs: Dict[str, Dict] = defaultdict(lambda: {"unique": set(), "long": 0, "max_len": 0, "clients": set()})
    total = 0

    for ts, client, query, qtype in iter_queries(iter_lines(args.files)):
        total += 1
        query = query.lower().rstrip(".")
        sub, label, reg = split_domain(query)
        if allowed(reg, allow):
            continue
        pair_times[(client, reg)].append(ts)
        if reg not in dga:
            score = dga_score(label)
            if score >= args.dga_threshold:
                dga[reg] = {"domain": reg, "score": score, "entropy": round(entropy(label), 2),
                            "length": len(label), "clients": set(), "count": 0}
        if reg in dga:
            dga[reg]["clients"].add(client)
            dga[reg]["count"] += 1
        if sub:
            s = subs[reg]
            s["unique"].add(sub)
            s["clients"].add(client)
            s["max_len"] = max(s["max_len"], len(sub))
            if len(sub) >= args.tunnel_len:
                s["long"] += 1

    if total == 0:
        warn("DNS 질의를 하나도 해석하지 못했습니다 (입력 형식 확인)")

    beacons = []
    for (client, reg), times in pair_times.items():
        if len(times) < args.min_count:
            continue
        times.sort()
        gaps = [b - a for a, b in zip(times, times[1:]) if b - a > 0]
        if len(gaps) < args.min_count - 1:
            continue
        mean = statistics.mean(gaps)
        cv = statistics.pstdev(gaps) / mean if mean else 1
        if cv <= args.max_cv and mean >= args.min_interval:
            beacons.append({"client": client, "domain": reg, "queries": len(times),
                            "mean_interval_s": round(mean, 1), "cv": round(cv, 3),
                            "duration_min": round((times[-1] - times[0]) / 60, 1)})
    beacons.sort(key=lambda r: r["cv"])

    # 동일 클라이언트가 DGA 의심 도메인을 여러 개 질의하면 감염 가능성이 높다
    per_client = Counter(c for d in dga.values() for c in d["clients"])
    dga_rows = sorted(({**d, "clients": sorted(d["clients"])} for d in dga.values()), key=lambda r: -r["score"])
    dga_clients = [{"client": c, "dga_domains": n} for c, n in per_client.most_common() if n >= 3]

    tunnels = [{"domain": reg, "unique_subdomains": len(s["unique"]), "long_queries": s["long"],
                "max_sub_len": s["max_len"], "clients": sorted(s["clients"])}
               for reg, s in subs.items()
               if s["long"] >= 5 or (len(s["unique"]) >= args.tunnel_unique and s["max_len"] >= args.tunnel_len // 2)]
    tunnels.sort(key=lambda r: -r["unique_subdomains"])

    emit_sections({"BEACON": beacons, "DGA": dga_rows, "DGA - clients (3+ domains)": dga_clients,
                   "TUNNELING": tunnels}, args.fmt)
    if args.fmt == "table":
        sys.stdout.flush()
        print(f"\n[*] 분석한 질의 {total}건", file=sys.stderr)
    return EXIT_DETECTED if (beacons or dga_rows or tunnels) else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
