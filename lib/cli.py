"""CLI 공통 헬퍼: 입력 읽기, 출력 형식 인자, 종료 코드."""
import argparse
import gzip
import sys
from pathlib import Path
from typing import Iterable, Iterator, List, Optional

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_DETECTED = 2


def setup_stdio() -> None:
    """Windows 파이프/리다이렉트에서도 한글이 깨지지 않도록 UTF-8로 통일."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except AttributeError:
            pass


def add_output_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--json", dest="fmt", action="store_const", const="json",
                       help="JSON으로 출력")
    group.add_argument("--csv", dest="fmt", action="store_const", const="csv",
                       help="CSV로 출력")
    parser.set_defaults(fmt="table")


def _open(path: str):
    if path == "-":
        return sys.stdin
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def iter_lines(paths: Optional[Iterable[str]]) -> Iterator[str]:
    """파일 목록(없으면 stdin)의 줄을 순서대로 돌려준다. .gz 자동 해제."""
    paths = list(paths or []) or ["-"]
    for path in paths:
        fh = _open(path)
        try:
            for line in fh:
                yield line.rstrip("\r\n")
        finally:
            if fh is not sys.stdin:
                fh.close()


def read_text(paths: Optional[Iterable[str]]) -> str:
    return "\n".join(iter_lines(paths))


def die(msg: str, code: int = EXIT_ERROR) -> "NoReturn":  # type: ignore[name-defined]
    print(f"[-] {msg}", file=sys.stderr)
    sys.exit(code)


def info(msg: str) -> None:
    print(f"[*] {msg}", file=sys.stderr)


def warn(msg: str) -> None:
    print(f"[!] {msg}", file=sys.stderr)


def check_files_exist(paths: List[str]) -> None:
    for p in paths:
        if p != "-" and not Path(p).is_file():
            die(f"파일을 찾을 수 없음: {p}")
