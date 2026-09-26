#!/usr/bin/env python3
"""SSH 무차별 대입(brute force) / 패스워드 스프레이 탐지 (auth.log, secure, journalctl 출력).

IP별로 실패 횟수·시도한 계정 수·성공 여부를 집계하고 아래 규칙으로 판정한다.
  BRUTEFORCE         : 실패 >= --threshold (기본 10)
  PASSWORD_SPRAY     : 서로 다른 계정 >= --spray-users (기본 5)
  COMPROMISE_SUSPECTED : 위 조건에 해당하는 IP에서 로그인 성공 기록 존재  ← 최우선 확인
종료 코드: 0=탐지 없음, 1=오류, 2=탐지 있음

예시:
  ssh_bruteforce.py /var/log/auth.log /var/log/auth.log.1 /var/log/auth.log.2.gz
  journalctl -u ssh --since today | ssh_bruteforce.py --threshold 5
  ssh_bruteforce.py /var/log/secure --all --csv > ssh_summary.csv
"""
import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib.cli import EXIT_DETECTED, EXIT_OK, add_output_args, check_files_exist, iter_lines, setup_stdio, warn  # noqa: E402
from lib.ioc_patterns import is_internal_ip  # noqa: E402
from lib.output import emit  # noqa: E402

TS_RE = re.compile(r"^(?:(\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})|(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}))")
FAILED_RE = re.compile(r"Failed (?:password|publickey|keyboard-interactive/pam) for (invalid user )?(\S+) from (\S+) port")
INVALID_RE = re.compile(r"Invalid user (\S*) from (\S+)(?: port|$)")
ACCEPTED_RE = re.compile(r"Accepted (\S+) for (\S+) from (\S+) port")
PAM_FAIL_RE = re.compile(r"authentication failure;.*\brhost=(\S+)(?:\s+user=(\S+))?")


def new_stat() -> Dict[str, Any]:
    return {"failures": 0, "invalid_users": 0, "users": set(), "accepted": [],
            "first_seen": None, "last_seen": None}


def parse(lines) -> Dict[str, Dict[str, Any]]:
    stats: Dict[str, Dict[str, Any]] = defaultdict(new_stat)
    for line in lines:
        if "sshd" not in line:
            continue
        m = TS_RE.match(line)
        ts = (m.group(1) or m.group(2)) if m else ""

        ip = None
        if (m := FAILED_RE.search(line)):
            invalid, user, ip = m.groups()
            s = stats[ip]
            s["failures"] += 1
            s["users"].add(user)
            if invalid:
                s["invalid_users"] += 1
        elif (m := ACCEPTED_RE.search(line)):
            method, user, ip = m.groups()
            stats[ip]["accepted"].append({"time": ts, "user": user, "method": method})
        elif (m := INVALID_RE.search(line)):
            # "Invalid user" 줄은 뒤따르는 "Failed password" 와 중복되므로 계정만 기록
            user, ip = m.groups()
            stats[ip]["users"].add(user or "(empty)")
        elif (m := PAM_FAIL_RE.search(line)) and "sshd" in line:
            ip = m.group(1)
            if m.group(2):
                stats[ip]["users"].add(m.group(2))

        if ip:
            s = stats[ip]
            s["first_seen"] = s["first_seen"] or ts
            s["last_seen"] = ts
    return stats


def evaluate(stats, threshold: int, spray_users: int) -> List[Dict[str, Any]]:
    rows = []
    for ip, s in stats.items():
        flags = []
        if s["failures"] >= threshold:
            flags.append("BRUTEFORCE")
        if len(s["users"]) >= spray_users:
            flags.append("PASSWORD_SPRAY")
        if flags and s["accepted"]:
            flags.insert(0, "COMPROMISE_SUSPECTED")
        success_users = sorted({a["user"] for a in s["accepted"]})
        rows.append({
            "ip": ip,
            "scope": "internal" if is_internal_ip(ip) else "external",
            "failures": s["failures"],
            "invalid_users": s["invalid_users"],
            "unique_users": len(s["users"]),
            "success": len(s["accepted"]),
            "success_users": success_users,
            "first_seen": s["first_seen"],
            "last_seen": s["last_seen"],
            "flags": flags,
            "tried_users": sorted(s["users"]),
        })
    severity = {"COMPROMISE_SUSPECTED": 0, "BRUTEFORCE": 1, "PASSWORD_SPRAY": 2}
    rows.sort(key=lambda r: (min((severity[f] for f in r["flags"]), default=9), -r["failures"]))
    return rows


def main() -> int:
    setup_stdio()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="*", help="auth 로그 파일 (생략 시 stdin, .gz 지원)")
    ap.add_argument("-t", "--threshold", type=int, default=10, help="BRUTEFORCE 판정 실패 횟수 (기본 10)")
    ap.add_argument("-u", "--spray-users", type=int, default=5, help="PASSWORD_SPRAY 판정 계정 수 (기본 5)")
    ap.add_argument("-a", "--all", action="store_true", help="탐지되지 않은 IP도 모두 출력")
    ap.add_argument("--show-users", action="store_true", help="시도한 계정 목록 컬럼 추가")
    add_output_args(ap)
    args = ap.parse_args()
    check_files_exist(args.files)

    rows = evaluate(parse(iter_lines(args.files)), args.threshold, args.spray_users)
    flagged = [r for r in rows if r["flags"]]
    out = rows if args.all else flagged

    columns = ["ip", "scope", "flags", "failures", "unique_users", "success", "success_users",
               "first_seen", "last_seen"]
    if args.show_users:
        columns.append("tried_users")
    emit(out, args.fmt, columns=columns, title="SSH Brute-force Summary")

    compromised = [r["ip"] for r in flagged if "COMPROMISE_SUSPECTED" in r["flags"]]
    sys.stdout.flush()
    if compromised:
        warn(f"공격 IP에서 로그인 성공! 즉시 확인 필요: {', '.join(compromised)}")
    return EXIT_DETECTED if flagged else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
