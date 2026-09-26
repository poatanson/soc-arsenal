#!/usr/bin/env python3
"""IOC 목록을 VirusTotal / AbuseIPDB / urlscan.io 로 평판 조회한다.

API 키(VT_API_KEY, ABUSEIPDB_API_KEY, URLSCAN_API_KEY)는 환경변수나 저장소 루트의
.env 파일에서 읽는다. 키가 없는 제공자는 건너뛰며, 키가 하나도 없으면
IOC 분류(오프라인)만 수행한다. 결과는 ~/.cache/soc-arsenal 에 24시간 캐시된다.

판정 기준:
  malicious  : VT 악성 탐지 >= 3  또는 AbuseIPDB 점수 >= 75
  suspicious : VT 악성/의심 탐지 >= 1 또는 AbuseIPDB 점수 >= 25
종료 코드: 0=정상, 1=오류, 2=malicious 판정 존재

예시:
  ioc_enrich.py iocs.txt
  ioc_extract.py report.txt --plain --public-only | ioc_enrich.py --csv > enriched.csv
  ioc_enrich.py --providers abuseipdb 203.0.113.50
"""
import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib import ti_client  # noqa: E402
from lib.cli import (EXIT_DETECTED, EXIT_OK, add_output_args, check_files_exist,  # noqa: E402
                     die, info, read_text, setup_stdio, warn)
from lib.ioc_patterns import classify, extract_iocs, is_public_ip, refang  # noqa: E402
from lib.output import emit  # noqa: E402

PROVIDERS = ("virustotal", "abuseipdb", "urlscan")


def collect_iocs(raw: str) -> List[Dict[str, str]]:
    """한 줄에 하나씩이면 그대로 분류, 아니면 자유 텍스트로 보고 추출."""
    items: Dict[str, str] = {}
    leftovers = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        value = refang(line.split(",")[0].strip())
        ioc_type = classify(value)
        if ioc_type == "unknown":
            leftovers.append(line)
        else:
            items.setdefault(value if ioc_type == "url" else value.lower(), ioc_type)
    if leftovers:
        for ioc_type, values in extract_iocs("\n".join(leftovers)).items():
            for v in values:
                items.setdefault(v, ioc_type)
    return [{"ioc": k, "type": v} for k, v in items.items()]


def verdict(vt: Dict[str, Any], abuse: Dict[str, Any]) -> str:
    vt_mal = vt.get("malicious", 0) if vt.get("status") == "ok" else 0
    vt_sus = vt.get("suspicious", 0) if vt.get("status") == "ok" else 0
    score = abuse.get("abuse_score", 0) if abuse.get("status") == "ok" else 0
    if vt_mal >= 3 or score >= 75:
        return "malicious"
    if vt_mal + vt_sus >= 1 or score >= 25:
        return "suspicious"
    if vt.get("status") == "ok" or abuse.get("status") == "ok":
        return "clean"
    return "unknown"


def enrich(item: Dict[str, str], providers: List[str], use_cache: bool) -> Dict[str, Any]:
    ioc, ioc_type = item["ioc"], item["type"]
    row: Dict[str, Any] = {"ioc": ioc, "type": ioc_type}
    vt: Dict[str, Any] = {}
    abuse: Dict[str, Any] = {}

    if ioc_type in ("ipv4", "ipv6") and not is_public_ip(ioc):
        row.update(verdict="private", note="사설/예약 IP - 조회 생략")
        return row

    if "virustotal" in providers:
        vt = ti_client.virustotal(ioc, ioc_type, use_cache=use_cache)
        if vt.get("status") == "ok":
            row["vt"] = f"{vt['malicious']}/{vt['malicious'] + vt['suspicious'] + vt['harmless'] + vt['undetected']}"
            row["vt_link"] = vt.get("link")
        else:
            row["vt"] = vt.get("error") or vt.get("status")
    if "abuseipdb" in providers and ioc_type in ("ipv4", "ipv6"):
        abuse = ti_client.abuseipdb(ioc, use_cache=use_cache)
        if abuse.get("status") == "ok":
            row["abuse_score"] = abuse["abuse_score"]
            row["reports"] = abuse["total_reports"]
            row["country"] = abuse.get("country")
            row["isp"] = abuse.get("isp")
        else:
            row["abuse_score"] = abuse.get("error") or abuse.get("status")
    if "urlscan" in providers and ioc_type in ("domain", "url", "ipv4", "ipv6", "sha256"):
        us = ti_client.urlscan_search(ioc, ioc_type, use_cache=use_cache)
        row["urlscan"] = us.get("total_scans") if us.get("status") == "ok" else (us.get("error") or us.get("status"))

    row["verdict"] = verdict(vt, abuse)
    return row


def main() -> int:
    setup_stdio()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="*", help="IOC 값 또는 파일 경로 (생략 시 stdin)")
    ap.add_argument("-p", "--providers", default=",".join(PROVIDERS),
                    help="사용할 제공자 (기본: virustotal,abuseipdb,urlscan)")
    ap.add_argument("--no-cache", action="store_true", help="캐시 무시하고 새로 조회")
    ap.add_argument("--max", type=int, default=100, help="최대 조회 IOC 수 (기본 100, 무료 API 한도 보호)")
    add_output_args(ap)
    args = ap.parse_args()

    providers = [p.strip() for p in args.providers.split(",") if p.strip()]
    bad = [p for p in providers if p not in PROVIDERS]
    if bad:
        die(f"알 수 없는 제공자: {', '.join(bad)}")

    files = [i for i in args.inputs if Path(i).is_file()]
    literals = [i for i in args.inputs if i not in files]
    if files:
        check_files_exist(files)
    raw = "\n".join(literals) + "\n" + (read_text(files) if files or not literals else "")
    items = collect_iocs(raw)
    if not items:
        die("조회할 IOC가 없습니다")
    if len(items) > args.max:
        warn(f"IOC {len(items)}개 중 앞의 {args.max}개만 조회합니다 (--max 로 조정)")
        items = items[: args.max]

    available = ti_client.available_providers()
    active = [p for p in providers if available[p]]
    missing = [p for p in providers if not available[p]]
    if missing:
        warn(f"API 키 없음 → 건너뜀: {', '.join(missing)} (.env.example 참고)")
    if not active:
        warn("사용 가능한 제공자가 없어 오프라인 분류만 수행합니다")
    elif "virustotal" in active:
        info("VirusTotal 무료 한도(4회/분) 준수를 위해 요청 간 15초 대기합니다 (캐시된 항목 제외)")

    rows = []
    for n, item in enumerate(items, 1):
        if active:
            info(f"[{n}/{len(items)}] {item['type']:<7} {item['ioc']}")
            rows.append(enrich(item, active, use_cache=not args.no_cache))
        else:
            rows.append({**item, "verdict": "private" if item["type"] in ("ipv4", "ipv6")
                         and not is_public_ip(item["ioc"]) else "not_checked"})

    columns = ["ioc", "type", "verdict"]
    for col in ("vt", "abuse_score", "reports", "country", "isp", "urlscan", "vt_link", "note"):
        if any(col in r for r in rows):
            columns.append(col)
    emit(rows, args.fmt, columns=columns, title="IOC Enrichment")

    malicious = [r for r in rows if r.get("verdict") == "malicious"]
    if malicious:
        warn(f"악성 판정 {len(malicious)}건")
        return EXIT_DETECTED
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
