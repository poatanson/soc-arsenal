#!/usr/bin/env python3
"""SSH 무차별 대입(brute force) / 패스워드 스프레이 탐지 (auth.log, secure, journalctl 출력).

IP별로 실패 횟수·시도한 계정 수·성공 여부를 집계하고 아래 규칙으로 판정한다.
  BRUTEFORCE         : 실패 >= --threshold (기본 10)
                       --window N 지정 시 "N분 슬라이딩 윈도우 안의 실패 >= --threshold"
  PASSWORD_SPRAY     : 서로 다른 계정 >= --spray-users (기본 5, 윈도우와 무관하게 전체 기간 기준)
  COMPROMISE_SUSPECTED : 위 조건에 해당하는 IP에서 로그인 성공 기록 존재  ← 최우선 확인
종료 코드: 0=탐지 없음, 1=오류, 2=탐지 있음

예시:
  ssh_bruteforce.py /var/log/auth.log /var/log/auth.log.1 /var/log/auth.log.2.gz
  ssh_bruteforce.py /var/log/auth.log* --threshold 10 --window 5
  journalctl -u ssh --since today | ssh_bruteforce.py --threshold 5
  ssh_bruteforce.py /var/log/secure --all --csv > ssh_summary.csv
  ssh_bruteforce.py old_auth.log --window 5 --year 2024   # 연도 없는 syslog 포맷의 과거 로그
"""
import argparse
import re
import sys
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Deque, Dict, List, NamedTuple, Optional, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib.cli import EXIT_DETECTED, EXIT_OK, add_output_args, check_files_exist, iter_lines, setup_stdio, warn  # noqa: E402
from lib.ioc_patterns import is_internal_ip  # noqa: E402
from lib.output import emit  # noqa: E402

TS_RE = re.compile(r"^(?:(\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})|(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}))")
FAILED_RE = re.compile(r"Failed (?:password|publickey|keyboard-interactive/pam) for (invalid user )?(\S+) from (\S+) port")
INVALID_RE = re.compile(r"Invalid user (\S*) from (\S+)(?: port|$)")
ACCEPTED_RE = re.compile(r"Accepted (\S+) for (\S+) from (\S+) port")
PAM_FAIL_RE = re.compile(r"authentication failure;.*\brhost=(\S+)(?:\s+user=(\S+))?")

# strptime 의 %b 는 로케일(ko_KR 등)에 따라 달라지므로 월 이름은 직접 매핑
MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}
DT_FMT = "%Y-%m-%d %H:%M:%S"


def to_datetime(ts: str, year: Optional[int] = None, now: Optional[datetime] = None) -> Optional[datetime]:
    """TS_RE 로 뽑은 타임스탬프 문자열을 비교 가능한 datetime 으로 변환 (실패 시 None).

    ISO 형식(2026-09-26T03:20:01)은 그대로 파싱한다. 오프셋(+09:00)·소수초는 TS_RE 단계에서
    잘려 나가므로 서로 다른 타임존의 로그를 섞으면 시간 비교가 어긋날 수 있다.

    연도가 없는 syslog 형식(Jan  5 03:14:07)의 연도 결정 방침:
      - year 지정(--year) 시: 모든 줄에 그 연도를 그대로 적용한다.
      - 미지정 시: "현재 연도"를 가정하되, 그 결과가 미래(now + 1일 초과)이면 작년으로 본다.
        → 1월에 읽는 12월 로그, 연말~연초에 걸친 auth.log.1 등 대부분의 로테이션 상황을 처리.
    한계:
      - 1년 넘게 지난 로그는 연도를 알 수 없어 1년 이내로 잘못 배치된다 → --year 로 지정할 것.
      - --year 지정 시에는 연도 롤오버(12/31 → 1/1)를 감지하지 못한다 (한 해 분량씩 나눠 분석).
      - 평년으로 가정된 해의 2월 29일은 표현할 수 없어 작년(윤년이면) 또는 None 이 된다.
      - 판정은 분석 머신의 현재 시각 기준이므로 로그 수집 호스트와 시계/타임존이 다르면 오차가 생긴다.
    """
    if ts[:1].isdigit():
        try:
            return datetime.strptime(ts.replace("T", " "), DT_FMT)
        except ValueError:
            return None
    try:
        mon_name, day, hms = ts.split()
        mon = MONTHS[mon_name]
        h, mi, s = (int(x) for x in hms.split(":"))
        d = int(day)
    except (KeyError, ValueError):
        return None

    if year is not None:
        try:
            return datetime(year, mon, d, h, mi, s)
        except ValueError:
            return None
    now = now or datetime.now()
    for y in (now.year, now.year - 1):
        try:
            dt = datetime(y, mon, d, h, mi, s)
        except ValueError:  # 평년의 2/29
            continue
        if dt <= now + timedelta(days=1):  # 1일 여유: 호스트 간 시계/타임존 차이 흡수
            return dt
    return None


class Burst(NamedTuple):
    detected_at: Optional[datetime]  # 윈도우 내 이벤트 수가 threshold 에 처음 도달한 시점 (미도달 시 None)
    count_at_detection: int          # 그 시점의 윈도우 내 이벤트 수 (한 건씩 늘어나므로 정의상 == threshold)
    peak_count: int                  # 전체 기간 중 한 윈도우에 들어간 최대 이벤트 수
    peak_start: Optional[datetime]
    peak_end: Optional[datetime]


def sliding_window_burst(times: Sequence[datetime], window_minutes: int, threshold: int) -> Burst:
    """정렬된 타임스탬프 목록에 길이 window_minutes 분의 슬라이딩 윈도우를 적용한다.

    deque 가 곧 윈도우다: 오른쪽 포인터(append)가 이벤트를 하나씩 넣고, 왼쪽 포인터(popleft)가
    닫힌 구간 [t - window, t] 를 벗어난 오래된 이벤트를 밀어낸다. 각 이벤트는 한 번씩만
    들어오고 나가므로 O(n).
    전제: times 는 오름차순이어야 한다. 섞여 있으면 popleft 조건이 깨져 윈도우 내 개수를
    잘못(주로 과소) 집계하므로 호출 측에서 반드시 sorted() 할 것.
    """
    span = timedelta(minutes=window_minutes)
    win: Deque[datetime] = deque()
    detected_at: Optional[datetime] = None
    count_at = 0
    peak, peak_start, peak_end = 0, None, None
    for t in times:
        win.append(t)
        while t - win[0] > span:
            win.popleft()
        n = len(win)
        if detected_at is None and n >= threshold:
            detected_at, count_at = t, n
        if n > peak:
            peak, peak_start, peak_end = n, win[0], t
    return Burst(detected_at, count_at, peak, peak_start, peak_end)


def new_stat() -> Dict[str, Any]:
    return {"failures": 0, "fail_times": [], "untimed_failures": 0, "invalid_users": 0,
            "users": set(), "accepted": [],
            "first_seen": None, "last_seen": None, "first_dt": None, "last_dt": None}


def parse(lines, year: Optional[int] = None) -> Dict[str, Dict[str, Any]]:
    stats: Dict[str, Dict[str, Any]] = defaultdict(new_stat)
    now = datetime.now()
    for line in lines:
        if "sshd" not in line:
            continue
        m = TS_RE.match(line)
        ts = (m.group(1) or m.group(2)) if m else ""
        dt = to_datetime(ts, year, now) if ts else None

        ip = None
        if (m := FAILED_RE.search(line)):
            invalid, user, ip = m.groups()
            s = stats[ip]
            s["failures"] += 1
            if dt:
                s["fail_times"].append(dt)
            else:
                s["untimed_failures"] += 1  # 윈도우 계산에서 제외됨
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
            if dt is None:
                # 파싱 불가한 타임스탬프는 기존처럼 등장 순서 기준
                s["first_seen"] = s["first_seen"] or ts
                s["last_seen"] = ts
            else:
                # 여러 파일을 섞어 넣으면 줄 순서 ≠ 시간 순서이므로 실제 시각으로 min/max 비교
                if s["first_dt"] is None or dt < s["first_dt"]:
                    s["first_dt"], s["first_seen"] = dt, ts
                if s["last_dt"] is None or dt >= s["last_dt"]:
                    s["last_dt"], s["last_seen"] = dt, ts
    return stats


def evaluate(stats, threshold: int, spray_users: int, window: Optional[int] = None) -> List[Dict[str, Any]]:
    rows = []
    for ip, s in stats.items():
        flags = []
        burst: Optional[Burst] = None
        if window is None:
            if s["failures"] >= threshold:
                flags.append("BRUTEFORCE")
        else:
            # auth.log, auth.log.1 ... 순으로 읽으면 최신 → 과거 순서가 되므로 정렬이 필수
            burst = sliding_window_burst(sorted(s["fail_times"]), window, threshold)
            if burst.detected_at:
                flags.append("BRUTEFORCE")
        # PASSWORD_SPRAY 는 low-and-slow(계정 잠금 회피용 저속 분산) 공격이 흔해 윈도우를 적용하지 않음
        if len(s["users"]) >= spray_users:
            flags.append("PASSWORD_SPRAY")
        if flags and s["accepted"]:
            flags.insert(0, "COMPROMISE_SUSPECTED")
        success_users = sorted({a["user"] for a in s["accepted"]})
        row = {
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
        }
        if burst is not None:
            row["burst_window"] = f"{burst.peak_count}회/{window}분" if burst.peak_count else ""
            row["burst_detected_at"] = burst.detected_at.strftime(DT_FMT) if burst.detected_at else ""
            row["burst_peak"] = (f"{burst.peak_start.strftime(DT_FMT)} ~ {burst.peak_end.strftime(DT_FMT)}"
                                 if burst.peak_start else "")
        rows.append(row)
    severity = {"COMPROMISE_SUSPECTED": 0, "BRUTEFORCE": 1, "PASSWORD_SPRAY": 2}
    rows.sort(key=lambda r: (min((severity[f] for f in r["flags"]), default=9), -r["failures"]))
    return rows


def positive_int(value: str) -> int:
    n = int(value)
    if n <= 0:
        raise argparse.ArgumentTypeError("1 이상의 정수여야 함")
    return n


def main() -> int:
    setup_stdio()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="*", help="auth 로그 파일 (생략 시 stdin, .gz 지원)")
    ap.add_argument("-t", "--threshold", type=int, default=10, help="BRUTEFORCE 판정 실패 횟수 (기본 10)")
    ap.add_argument("-u", "--spray-users", type=int, default=5, help="PASSWORD_SPRAY 판정 계정 수 (기본 5)")
    ap.add_argument("-w", "--window", type=positive_int, default=None, metavar="MIN",
                    help="분 단위 슬라이딩 윈도우 안에서 --threshold 이상 실패 시 BRUTEFORCE "
                         "(기본: 미사용 = 전체 기간 누적)")
    ap.add_argument("--year", type=int, default=None,
                    help="연도 없는 syslog 타임스탬프에 적용할 연도 (기본: 현재 연도 가정, 미래면 작년)")
    ap.add_argument("-a", "--all", action="store_true", help="탐지되지 않은 IP도 모두 출력")
    ap.add_argument("--show-users", action="store_true", help="시도한 계정 목록 컬럼 추가")
    add_output_args(ap)
    args = ap.parse_args()
    check_files_exist(args.files)

    stats = parse(iter_lines(args.files), args.year)
    rows = evaluate(stats, args.threshold, args.spray_users, args.window)
    flagged = [r for r in rows if r["flags"]]
    out = rows if args.all else flagged

    columns = ["ip", "scope", "flags", "failures", "unique_users", "success", "success_users",
               "first_seen", "last_seen"]
    if args.window is not None:
        columns[4:4] = ["burst_window", "burst_detected_at", "burst_peak"]
    if args.show_users:
        columns.append("tried_users")
    emit(out, args.fmt, columns=columns, title="SSH Brute-force Summary")

    sys.stdout.flush()
    if args.window is not None:
        untimed = sum(s["untimed_failures"] for s in stats.values())
        if untimed:
            warn(f"타임스탬프를 해석하지 못한 실패 {untimed}건은 윈도우 판정에서 제외됨")
    compromised = [r["ip"] for r in flagged if "COMPROMISE_SUSPECTED" in r["flags"]]
    if compromised:
        warn(f"공격 IP에서 로그인 성공! 즉시 확인 필요: {', '.join(compromised)}")
    return EXIT_DETECTED if flagged else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
