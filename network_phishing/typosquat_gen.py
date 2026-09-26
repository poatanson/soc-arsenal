#!/usr/bin/env python3
"""타이포스쿼팅 / 유사 도메인 생성 및 탐지 (브랜드 사칭 도메인 헌팅).

두 가지 모드:
  1) 생성: 보호 대상 도메인의 변형 목록 생성 (+ --resolve 로 실제 등록·해석 여부 확인)
  2) 검사: --check 로 프록시/DNS 로그 등에서 뽑은 도메인 목록 중 유사 도메인 찾기
           (변형 목록 일치 + 편집 거리 기반)

변형 기법: omission, repetition, transposition, replacement(인접 키), insertion,
          homoglyph(0↔o, rn↔m ...), vowel-swap, hyphenation, subdomain, bitsquatting,
          tld-swap, idn-homoglyph(키릴 문자 → punycode), addition, brand-keyword(login-, -secure ...)

예시:
  typosquat_gen.py example.com
  typosquat_gen.py example.com --resolve --registered-only
  typosquat_gen.py paypal.com --check observed_domains.txt
  ioc_extract.py proxy.log --plain --types domain | typosquat_gen.py mybank.co.kr --check -
"""
import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib.cli import EXIT_DETECTED, EXIT_OK, add_output_args, die, iter_lines, setup_stdio  # noqa: E402
from lib.output import emit  # noqa: E402

KEYBOARD = {
    "q": "12wa", "w": "23qeas", "e": "34wrsd", "r": "45etdf", "t": "56ryfg", "y": "67tugh",
    "u": "78yihj", "i": "89uojk", "o": "90ipkl", "p": "0-ol", "a": "qwsz", "s": "weadzx",
    "d": "erfcxs", "f": "rtgvcd", "g": "tyhbvf", "h": "yujnbg", "j": "uikmnh", "k": "iolmj",
    "l": "opk", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm",
    "m": "njk", "1": "2q", "2": "13wq", "3": "24ew", "4": "35re", "5": "46tr", "6": "57yt",
    "7": "68uy", "8": "79iu", "9": "80oi", "0": "9po",
}
HOMOGLYPHS = {
    "a": ["4", "@"], "b": ["d", "lb"], "c": ["e"], "d": ["b", "cl"], "e": ["3", "c"],
    "g": ["q", "9"], "h": ["lh"], "i": ["1", "l", "!"], "l": ["1", "i", "I"], "m": ["rn", "nn"],
    "n": ["m", "r"], "o": ["0", "q"], "q": ["g"], "s": ["5", "z"], "t": ["7"], "u": ["v"],
    "v": ["u"], "w": ["vv"], "z": ["2", "s"], "0": ["o"], "1": ["l", "i"],
}
IDN_HOMOGLYPHS = {"a": "а", "c": "с", "e": "е", "o": "о", "p": "р", "x": "х", "y": "у", "i": "і", "j": "ј", "s": "ѕ"}
TLDS = ["com", "net", "org", "co", "io", "info", "biz", "xyz", "top", "online", "site", "app", "shop",
        "support", "live", "cc", "me", "us", "kr", "co.kr", "click", "link", "vip"]
BRAND_WORDS = ["login", "secure", "account", "verify", "support", "update", "auth", "signin", "service", "help"]
MULTI_TLDS = {"co.kr", "or.kr", "ne.kr", "go.kr", "ac.kr", "co.uk", "org.uk", "ac.uk", "com.au", "co.jp", "com.cn"}
VALID_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-")


def split_domain(domain: str) -> Tuple[str, str]:
    domain = domain.lower().strip().rstrip(".")
    parts = domain.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_TLDS:
        return ".".join(parts[:-2]), ".".join(parts[-2:])
    return ".".join(parts[:-1]), parts[-1]


def generate(domain: str) -> Dict[str, str]:
    """변형 도메인 → 기법 이름"""
    name, tld = split_domain(domain)
    label = name.split(".")[-1]
    prefix = name[: -len(label)]
    out: Dict[str, str] = {}

    def add(new_label: str, technique: str, new_tld: str = tld) -> None:
        if not new_label or new_label == label and new_tld == tld:
            return
        if new_label.startswith("-") or new_label.endswith("-"):
            return
        cand = f"{prefix}{new_label}.{new_tld}"
        if technique != "idn-homoglyph" and not set(new_label) <= VALID_CHARS | {"."}:
            return
        out.setdefault(cand, technique)

    n = len(label)
    for i in range(n):
        add(label[:i] + label[i + 1:], "omission")
        add(label[:i] + label[i] + label[i:], "repetition")
        if i < n - 1 and label[i] != label[i + 1]:
            add(label[:i] + label[i + 1] + label[i] + label[i + 2:], "transposition")
        for ch in KEYBOARD.get(label[i], ""):
            add(label[:i] + ch + label[i + 1:], "replacement")
            add(label[:i] + ch + label[i:], "insertion")
        for g in HOMOGLYPHS.get(label[i], []):
            add(label[:i] + g.lower() + label[i + 1:], "homoglyph")
        if label[i] in "aeiou":
            for v in "aeiou":
                if v != label[i]:
                    add(label[:i] + v + label[i + 1:], "vowel-swap")
        if 0 < i:
            add(label[:i] + "-" + label[i:], "hyphenation")
            add(label[:i] + "." + label[i:], "subdomain")
        for bit in range(8):
            c = chr(ord(label[i]) ^ (1 << bit))
            if c in VALID_CHARS and c != "-":
                add(label[:i] + c + label[i + 1:], "bitsquatting")
        if label[i] in IDN_HOMOGLYPHS:
            try:
                idn = (label[:i] + IDN_HOMOGLYPHS[label[i]] + label[i + 1:]).encode("idna").decode()
                add(idn, "idn-homoglyph")
            except UnicodeError:
                pass
    for ch in "abcdefghijklmnopqrstuvwxyz0123456789":
        add(label + ch, "addition")
    for t in TLDS:
        if t != tld:
            add(label, "tld-swap", t)
    for w in BRAND_WORDS:
        add(f"{w}-{label}", "brand-keyword")
        add(f"{label}-{w}", "brand-keyword")
        add(f"{label}{w}", "brand-keyword")
    return out


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def resolve(domain: str) -> List[str]:
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)})
    except (socket.gaierror, UnicodeError, OSError):
        return []


def check_observed(protected: str, observed: List[str], variants: Dict[str, str], max_dist: int) -> List[Dict]:
    p_name, _ = split_domain(protected)
    p_label = p_name.split(".")[-1]
    p_base = ".".join(split_domain(protected))
    hits = []
    seen: Set[str] = set()
    for d in observed:
        d = d.strip().lower().rstrip(".")
        if not d or d in seen or d == p_base or d.endswith("." + p_base):
            continue
        seen.add(d)
        name, tld = split_domain(d)
        base = f"{name.split('.')[-1]}.{tld}" if name else d
        label = name.split(".")[-1] if name else ""
        if d in variants or base in variants:
            hits.append({"domain": d, "technique": variants.get(d) or variants.get(base), "distance": levenshtein(label, p_label)})
            continue
        if not label:
            continue
        dist = levenshtein(label, p_label)
        if 0 < dist <= max_dist and len(p_label) >= 4:
            hits.append({"domain": d, "technique": f"edit-distance-{dist}", "distance": dist})
        elif p_label in label and label != p_label and len(p_label) >= 4:
            hits.append({"domain": d, "technique": "brand-contained", "distance": dist})
        elif p_label in name.split(".")[:-1]:
            hits.append({"domain": d, "technique": "brand-in-subdomain", "distance": dist})
    hits.sort(key=lambda h: h["distance"])
    return hits


def main() -> int:
    setup_stdio()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("domain", help="보호 대상 도메인 (예: example.com)")
    ap.add_argument("-c", "--check", metavar="FILE", help="관측 도메인 목록 파일에서 유사 도메인 탐지 ('-' = stdin)")
    ap.add_argument("-d", "--max-distance", type=int, default=2, help="--check 편집 거리 임계치 (기본 2)")
    ap.add_argument("-r", "--resolve", action="store_true", help="생성된 도메인 DNS 해석 (등록 여부 확인)")
    ap.add_argument("--registered-only", action="store_true", help="--resolve 시 해석되는 도메인만 출력")
    ap.add_argument("-t", "--threads", type=int, default=32, help="--resolve 동시 요청 수 (기본 32)")
    ap.add_argument("--techniques", help="특정 기법만 (쉼표 구분)")
    add_output_args(ap)
    args = ap.parse_args()

    if "." not in args.domain:
        die("도메인 형식이 아닙니다 (예: example.com)")
    variants = generate(args.domain)
    if args.techniques:
        wanted = {t.strip() for t in args.techniques.split(",")}
        variants = {d: t for d, t in variants.items() if t in wanted}

    if args.check:
        observed = [line.split(",")[0].split()[0] for line in iter_lines([args.check]) if line.strip() and not line.startswith("#")]
        hits = check_observed(args.domain, observed, variants, args.max_distance)
        emit(hits, args.fmt, columns=["domain", "technique", "distance"], title=f"{args.domain} 유사 도메인 탐지")
        return EXIT_DETECTED if hits else EXIT_OK

    rows = [{"domain": d, "technique": t} for d, t in variants.items()]
    if args.resolve:
        print(f"[*] {len(rows)}개 도메인 DNS 해석 중...", file=sys.stderr)
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            for row, ips in zip(rows, pool.map(resolve, [r["domain"] for r in rows])):
                row["resolves"] = bool(ips)
                row["ips"] = ips
        if args.registered_only:
            rows = [r for r in rows if r["resolves"]]
    columns = ["domain", "technique"] + (["resolves", "ips"] if args.resolve else [])
    emit(rows, args.fmt, columns=columns, title=f"{args.domain} 변형 도메인")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
