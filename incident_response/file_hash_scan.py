#!/usr/bin/env python3
"""디렉터리를 해시 스캔해 알려진 악성 해시 목록과 대조한다.

악성 해시 목록은 어떤 형식이든 된다 (TXT/CSV/위협 보고서/MISP export 등) —
파일 안의 MD5/SHA1/SHA256 을 모두 뽑아서 사용하고, 같은 줄의 나머지 텍스트를 설명으로 쓴다.

예시:
  file_hash_scan.py /tmp /var/tmp /dev/shm -k known_bad.txt
  file_hash_scan.py /opt/app --manifest > baseline.csv        # 기준선(baseline) 생성
  file_hash_scan.py /opt/app --baseline baseline.csv          # 기준선 대비 변경/추가 파일 탐지
종료 코드: 0=일치 없음, 1=오류, 2=악성 일치 또는 기준선 변경 있음
"""
import argparse
import csv
import fnmatch
import hashlib
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib.cli import EXIT_DETECTED, EXIT_OK, add_output_args, die, info, setup_stdio, warn  # noqa: E402
from lib.ioc_patterns import MD5_RE, SHA1_RE, SHA256_RE  # noqa: E402
from lib.output import emit  # noqa: E402


def load_known_bad(paths: List[str]) -> Dict[str, str]:
    known: Dict[str, str] = {}
    for p in paths:
        for line in Path(p).read_text(encoding="utf-8", errors="replace").splitlines():
            if line.lstrip().startswith("#"):
                continue
            hashes = SHA256_RE.findall(line) + SHA1_RE.findall(line) + MD5_RE.findall(line)
            if not hashes:
                continue
            desc = line
            for h in hashes:
                desc = desc.replace(h, "")
            desc = desc.strip(" ,;\t|") or Path(p).name
            for h in hashes:
                known.setdefault(h.lower(), desc)
    return known


def iter_files(roots: List[str], excludes: List[str], max_size: int, follow: bool) -> Iterator[Path]:
    for root in roots:
        rp = Path(root)
        if rp.is_file():
            yield rp
            continue
        if not rp.is_dir():
            warn(f"존재하지 않음: {root}")
            continue
        for dirpath, dirnames, filenames in os.walk(rp, followlinks=follow, onerror=lambda e: warn(f"접근 불가: {e.filename}")):
            dirnames[:] = [d for d in dirnames if not any(fnmatch.fnmatch(d, x) for x in excludes)]
            for name in filenames:
                if any(fnmatch.fnmatch(name, x) for x in excludes):
                    continue
                path = Path(dirpath) / name
                try:
                    if not path.is_file() or (not follow and path.is_symlink()):
                        continue
                    if max_size and path.stat().st_size > max_size:
                        continue
                except OSError:
                    continue
                yield path


def hash_file(path: Path) -> Optional[Tuple[str, str, str]]:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
    except OSError as e:
        warn(f"읽기 실패: {path} ({e.strerror})")
        return None
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


def main() -> int:
    setup_stdio()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="스캔할 디렉터리/파일")
    ap.add_argument("-k", "--known-bad", action="append", default=[], help="악성 해시 목록 파일 (여러 번 지정 가능)")
    ap.add_argument("-b", "--baseline", help="--manifest 로 만든 기준선 CSV와 비교")
    ap.add_argument("--manifest", action="store_true", help="전체 파일 해시 목록(CSV) 출력 → 기준선/증거 보존용")
    ap.add_argument("-x", "--exclude", action="append", default=[], help="제외 패턴 (fnmatch, 예: '*.log', 'node_modules')")
    ap.add_argument("--max-size", type=int, default=200, help="최대 파일 크기 MB (기본 200, 0=무제한)")
    ap.add_argument("--follow-symlinks", action="store_true", help="심볼릭 링크 따라가기")
    add_output_args(ap)
    args = ap.parse_args()

    if not (args.known_bad or args.baseline or args.manifest):
        die("-k(악성 해시 목록), --baseline, --manifest 중 하나는 지정해야 합니다")
    for p in args.known_bad + ([args.baseline] if args.baseline else []):
        if not Path(p).is_file():
            die(f"파일을 찾을 수 없음: {p}")

    known = load_known_bad(args.known_bad)
    if args.known_bad:
        info(f"악성 해시 {len(known)}개 로드")
    baseline: Dict[str, Dict[str, str]] = {}
    if args.baseline:
        with open(args.baseline, newline="", encoding="utf-8") as fh:
            baseline = {row["path"]: row for row in csv.DictReader(fh)}
        info(f"기준선 파일 {len(baseline)}개 로드")

    matches, changes, manifest = [], [], []
    seen = set()
    scanned = 0
    for path in iter_files(args.paths, args.exclude, args.max_size * 1024 * 1024, args.follow_symlinks):
        hashes = hash_file(path)
        if not hashes:
            continue
        scanned += 1
        md5, sha1, sha256 = hashes
        st = path.stat()
        mtime = datetime.fromtimestamp(st.st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        key = str(path)
        seen.add(key)
        rec = {"path": key, "size": st.st_size, "mtime": mtime, "md5": md5, "sha1": sha1, "sha256": sha256}
        if args.manifest:
            manifest.append(rec)
        for h in (sha256, sha1, md5):
            if h in known:
                matches.append({**rec, "matched": h, "description": known[h]})
                break
        if baseline:
            old = baseline.get(key)
            if old is None:
                changes.append({"status": "ADDED", **rec})
            elif old.get("sha256") != sha256:
                changes.append({"status": "MODIFIED", **rec, "old_sha256": old.get("sha256")})
    if baseline:
        scanned_roots = [str(Path(p)) for p in args.paths]
        for key, old in baseline.items():
            if key not in seen and any(key.startswith(r) for r in scanned_roots):
                changes.append({"status": "DELETED", "path": key, "sha256": old.get("sha256"), "mtime": old.get("mtime")})

    info(f"스캔한 파일 {scanned}개")
    if args.manifest:
        emit(manifest, "csv" if args.fmt == "table" else args.fmt,
             columns=["path", "size", "mtime", "md5", "sha1", "sha256"])
    if args.known_bad:
        emit(matches, args.fmt, columns=["path", "size", "mtime", "matched", "description"],
             title="Known-bad Hash Matches")
    if baseline:
        emit(changes, args.fmt, columns=["status", "path", "mtime", "sha256", "old_sha256"],
             title="Baseline Changes")
    sys.stdout.flush()
    if matches:
        warn(f"악성 해시 일치 {len(matches)}건!")
    return EXIT_DETECTED if (matches or changes) else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
