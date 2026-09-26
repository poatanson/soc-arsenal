#!/usr/bin/env bash
# log_timeline.sh - 서로 다른 형식의 로그를 하나의 시간순 타임라인으로 병합
#
# 사용법:
#   log_timeline.sh [-y YEAR] [-s START] [-e END] [-g REGEX] [-o OUT] <로그파일>...
#     -y  syslog 형식(연도 없음)에 붙일 연도 (기본: 올해)
#     -s  시작 시각 (포함, 접두 비교) 예: "2026-09-26 03:00"
#     -e  종료 시각 (포함, 접두 비교) 예: "2026-09-26 04"
#     -g  대소문자 무시 정규식으로 필터 (예: '203\.0\.113\.50|admin')
#     -o  결과를 파일로 저장 (기본: stdout)
#
# 지원 시각 형식 → "YYYY-MM-DD HH:MM:SS" 로 정규화 (타임존 오프셋은 변환하지 않음):
#   ISO 8601     2026-09-26T08:00:01Z / 2026-09-26 08:00:01
#   syslog       Sep 26 08:00:01
#   Apache/Nginx [26/Sep/2026:08:00:01 +0900]
#   슬래시 날짜   2026/09/26 08:00:01
#   epoch(Zeek)  1790409601.123456  (UTC로 변환)
# 시각이 없는 줄(스택 트레이스 등)은 같은 파일의 직전 시각을 물려받는다. .gz 자동 해제.
# 출력: 시각<TAB>소스파일<TAB>원본 줄
set -euo pipefail

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

YEAR="$(date +%Y)"
START=""
END=""
FILTER=""
OUT=""
while getopts ":y:s:e:g:o:h" opt; do
  case "$opt" in
    y) YEAR="$OPTARG" ;;
    s) START="$OPTARG" ;;
    e) END="$OPTARG" ;;
    g) FILTER="$OPTARG" ;;
    o) OUT="$OPTARG" ;;
    h) usage 0 ;;
    *) usage 1 ;;
  esac
done
shift $((OPTIND - 1))
[ $# -ge 1 ] || usage 1

read_log() {
  case "$1" in
    *.gz) gzip -dc -- "$1" ;;
    *)    cat -- "$1" ;;
  esac
}

normalize() {
  local src="$1"
  awk -v src="$src" -v year="$YEAR" -v start="$START" -v end="$END" '
    BEGIN {
      FS = "\n"
      split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", m, " ")
      for (i = 1; i <= 12; i++) mon[m[i]] = sprintf("%02d", i)
      last = ""; skipped = 0
    }
    function pad(n) { return sprintf("%02d", n) }
    # epoch 초 → UTC "YYYY-MM-DD HH:MM:SS" (Howard Hinnant civil_from_days)
    function epoch2iso(e,    days, secs, z, era, doe, yoe, y, doy, mp, d, mo) {
      e = int(e); days = int(e / 86400); secs = e - days * 86400
      z = days + 719468
      era = int((z >= 0 ? z : z - 146096) / 146097)
      doe = z - era * 146097
      yoe = int((doe - int(doe / 1460) + int(doe / 36524) - int(doe / 146096)) / 365)
      y = yoe + era * 400
      doy = doe - (365 * yoe + int(yoe / 4) - int(yoe / 100))
      mp = int((5 * doy + 2) / 153)
      d = doy - int((153 * mp + 2) / 5) + 1
      mo = mp < 10 ? mp + 3 : mp - 9
      if (mo <= 2) y++
      return sprintf("%04d-%02d-%02d %02d:%02d:%02d", y, mo, d, int(secs / 3600), int(secs % 3600 / 60), secs % 60)
    }
    {
      line = $0; ts = ""
      if (match(line, /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9][T ][0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) {
        ts = substr(line, 1, 10) " " substr(line, 12, 8)
      } else if (match(line, /^[0-9][0-9][0-9][0-9]\/[0-9][0-9]\/[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) {
        ts = substr(line, 1, 4) "-" substr(line, 6, 2) "-" substr(line, 9, 2) " " substr(line, 12, 8)
      } else if (match(line, /^[A-Z][a-z][a-z] +[0-9]+ [0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) {
        split(substr(line, 1, RLENGTH), p, / +/)
        if (p[1] in mon) ts = year "-" mon[p[1]] "-" pad(p[2]) " " p[3]
      } else if (match(line, /\[[0-9][0-9]\/[A-Z][a-z][a-z]\/[0-9][0-9][0-9][0-9]:[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) {
        s = substr(line, RSTART + 1, RLENGTH - 1)
        ts = substr(s, 8, 4) "-" mon[substr(s, 4, 3)] "-" substr(s, 1, 2) " " substr(s, 13, 8)
      } else if (match(line, /^1[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9](\.[0-9]+)?[ \t]/)) {
        ts = epoch2iso(substr(line, 1, 10))
      }
      if (ts == "") {
        if (last == "") { skipped++; next }
        ts = last
      }
      last = ts
      if (start != "" && ts < start) next
      if (end != "" && substr(ts, 1, length(end)) > end) next
      printf "%s\t%s\t%s\n", ts, src, line
    }
    END { if (skipped > 0) printf "[!] %s: 시각을 찾지 못한 줄 %d개 건너뜀\n", src, skipped > "/dev/stderr" }
  '
}

build() {
  local f
  for f in "$@"; do
    if [ ! -r "$f" ]; then
      echo "[!] 읽을 수 없음: $f" >&2
      continue
    fi
    read_log "$f" | tr -d '\r' | normalize "$(basename "$f")"
  done | {
    if [ -n "$FILTER" ]; then grep -Ei -- "$FILTER" || true; else cat; fi
  } | LC_ALL=C sort -s -t "$(printf '\t')" -k1,1
}

if [ -n "$OUT" ]; then
  build "$@" > "$OUT"
  echo "[*] 저장: $OUT ($(wc -l < "$OUT" | tr -d ' ')줄)" >&2
else
  build "$@"
fi
