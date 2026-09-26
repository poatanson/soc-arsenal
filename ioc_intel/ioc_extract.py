#!/usr/bin/env python3
"""위협 보고서·메일·HTML·로그 텍스트에서 IOC를 추출한다.

defang된 표기(hxxp, [.], (at) 등)를 자동 복원하고, 유형별로 중복 제거한다.

예시:
  ioc_extract.py report.txt
  cat report.html | ioc_extract.py --types ipv4,domain --public-only
  ioc_extract.py report.txt --defang --csv > iocs.csv
  ioc_extract.py report.txt --plain --types sha256 | ioc_enrich.py
"""
import argparse
import html
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib.cli import EXIT_OK, add_output_args, check_files_exist, die, read_text, setup_stdio  # noqa: E402
from lib.ioc_patterns import IOC_TYPES, defang, extract_iocs  # noqa: E402
from lib.output import emit  # noqa: E402


def main() -> int:
    setup_stdio()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="*", help="입력 파일 (생략 시 stdin, .gz 지원)")
    ap.add_argument("-t", "--types", help=f"추출할 유형 (쉼표 구분): {','.join(IOC_TYPES)}")
    ap.add_argument("--public-only", action="store_true", help="사설/예약 IP 제외")
    ap.add_argument("--no-refang", action="store_true", help="defang 표기 복원 안 함")
    ap.add_argument("--defang", action="store_true", help="결과를 defang 형태로 출력 (보고서/티켓 공유용)")
    ap.add_argument("--plain", action="store_true", help="값만 한 줄씩 출력 (파이프라인용)")
    add_output_args(ap)
    args = ap.parse_args()

    check_files_exist(args.files)
    wanted = IOC_TYPES
    if args.types:
        wanted = tuple(t.strip().lower() for t in args.types.split(","))
        bad = [t for t in wanted if t not in IOC_TYPES]
        if bad:
            die(f"알 수 없는 유형: {', '.join(bad)}")

    text = html.unescape(read_text(args.files))
    found = extract_iocs(text, do_refang=not args.no_refang, include_private=not args.public_only)

    rows = []
    for ioc_type in wanted:
        for value in found.get(ioc_type, []):
            rows.append({"type": ioc_type, "value": defang(value) if args.defang else value})

    if args.plain:
        for r in rows:
            print(r["value"])
    else:
        emit(rows, args.fmt, columns=["type", "value"], title="Extracted IOCs")
        if args.fmt == "table":
            sys.stdout.flush()
            counts = ", ".join(f"{t}={len(found[t])}" for t in wanted if found.get(t))
            print(f"\n[*] 합계 {len(rows)}개 ({counts or '없음'})", file=sys.stderr)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
