#!/usr/bin/env python3
"""IOC defang / refang 변환기.

티켓·메일·메신저에 IOC를 공유할 때 클릭/자동 링크를 막기 위해 defang하고,
분석 도구에 넣을 때는 refang으로 되돌린다.

예시:
  defang.py "http://evil.com/a.php 1.2.3.4"      → hxxp[://]evil[.]com/a.php 1[.]2[.]3[.]4
  defang.py --refang "hxxp[://]evil[.]com"       → http://evil.com
  cat iocs.txt | defang.py > iocs_defanged.txt
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib.cli import EXIT_OK, check_files_exist, iter_lines, setup_stdio  # noqa: E402
from lib.ioc_patterns import defang, refang  # noqa: E402


def main() -> int:
    setup_stdio()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("text", nargs="*", help="변환할 문자열 (생략 시 stdin, -f 로 파일 지정)")
    ap.add_argument("-f", "--file", action="append", default=[], help="입력 파일")
    ap.add_argument("-r", "--refang", action="store_true", help="defang → 원래 형태로 복원")
    args = ap.parse_args()

    convert = refang if args.refang else defang
    if args.text:
        for t in args.text:
            print(convert(t))
        return EXIT_OK
    check_files_exist(args.file)
    for line in iter_lines(args.file):
        print(convert(line))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
