#!/usr/bin/env bash
# suspicious_proc.sh - Linux 의심 프로세스 헌팅 (/proc 기반, 읽기 전용)
#
# 사용법:
#   sudo suspicious_proc.sh [-c CPU임계치] [-v]
#     -c  고CPU 판정 임계치(%) (기본: 80)
#     -v  각 탐지 프로세스의 상세(환경변수 일부, 열린 소켓, 부모 체인) 출력
#
# 탐지 항목:
#   - 실행 파일이 삭제되었거나(deleted) memfd(파일리스)에서 실행 중
#   - /tmp, /var/tmp, /dev/shm 등 임시 경로에서 실행 중
#   - 리버스 셸 / 다운로드-실행 / 인코딩 명령줄 패턴
#   - 커널 스레드처럼 위장한 이름([kworker] 등)인데 실제 실행 파일이 있는 경우
#   - LD_PRELOAD 가 설정된 프로세스
#   - 채굴기 흔적(xmrig, stratum) 및 고CPU 프로세스
#   - 의심 경로 바이너리가 네트워크 소켓을 열고 있는 경우
# 종료 코드: 0=의심 없음, 2=의심 프로세스 있음
set -uo pipefail

usage() { sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

CPU_LIMIT=80
VERBOSE=0
while getopts ":c:vh" opt; do
  case "$opt" in
    c) CPU_LIMIT="$OPTARG" ;;
    v) VERBOSE=1 ;;
    h) usage 0 ;;
    *) usage 1 ;;
  esac
done
export LC_ALL=C

if [ ! -d /proc/1 ]; then
  echo "[-] /proc 가 없습니다. Linux 에서 실행하세요." >&2
  exit 1
fi
[ "$(id -u)" -eq 0 ] || echo "[!] root 가 아니면 다른 사용자 프로세스의 exe/environ 을 볼 수 없습니다" >&2

COUNT_FILE="$(mktemp)"
trap 'rm -f "$COUNT_FILE"' EXIT
if [ -t 1 ]; then RED=$'\033[31m'; RST=$'\033[0m'; else RED=""; RST=""; fi

SELF=$$
CMD_SUSP='/dev/tcp/|/dev/udp/|bash -i|sh -i|(nc|ncat|netcat)[^|]* -e |socat[^|]*exec|mkfifo|python[23]?[^|]*-c[^|]*(socket|pty\.spawn)|perl[^|]*-e[^|]*socket|php[^|]*-r[^|]*fsockopen|ruby[^|]*-rsocket|(curl|wget)[^|;]*\|[[:space:]]*(ba)?sh|base64 (-d|--decode)|powershell|xmrig|minerd|stratum\+tcp|--donate-level|cryptonight'
TMP_PATHS='^(/tmp/|/var/tmp/|/dev/shm/|/run/user/|/var/run/user/)'

declare -A REPORTED

report() {
  local pid="$1" reason="$2" exe="$3" cmd="$4" user
  user="$(stat -c %U "/proc/$pid" 2>/dev/null || echo '?')"
  echo x >> "$COUNT_FILE"
  printf '%s[!]%s PID %-7s %-10s %-26s exe=%s\n      cmd=%s\n' "$RED" "$RST" "$pid" "$user" "$reason" "$exe" "${cmd:0:300}"
  if [ "$VERBOSE" -eq 1 ] && [ -z "${REPORTED[$pid]:-}" ]; then
    REPORTED[$pid]=1
    local ppid chain="" cur="$pid" i
    for i in 1 2 3 4 5 6; do
      ppid="$(awk '/^PPid:/ {print $2}' "/proc/$cur/status" 2>/dev/null)"
      [ -n "$ppid" ] && [ "$ppid" -gt 0 ] || break
      chain="$chain <- $ppid($(tr -d '\n' < "/proc/$ppid/comm" 2>/dev/null))"
      cur="$ppid"
    done
    echo "      parents:$chain"
    echo "      cwd=$(readlink "/proc/$pid/cwd" 2>/dev/null)"
    if command -v ss >/dev/null 2>&1; then
      ss -tanp 2>/dev/null | grep -E "pid=$pid," | sed 's/^/      sock: /' | head -5
    fi
  fi
}

for p in /proc/[0-9]*; do
  pid="${p#/proc/}"
  [ "$pid" = "$SELF" ] && continue
  [ -r "$p/status" ] || continue
  comm="$(tr -d '\n' < "$p/comm" 2>/dev/null || true)"
  cmd="$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null || true)"
  exe="$(readlink "$p/exe" 2>/dev/null || true)"

  # 커널 스레드는 cmdline 과 exe 가 비어 있다
  if [ -z "$cmd" ] && [ -z "$exe" ]; then
    continue
  fi

  case "$exe" in
    *" (deleted)") report "$pid" "deleted-executable" "$exe" "$cmd" ;;
  esac
  case "$exe" in
    /memfd:*) report "$pid" "fileless-memfd" "$exe" "$cmd" ;;
  esac
  if [[ "$exe" =~ $TMP_PATHS ]]; then
    report "$pid" "exec-from-temp-dir" "$exe" "$cmd"
  fi
  if echo "$cmd" | grep -Eiq -- "$CMD_SUSP"; then
    report "$pid" "suspicious-cmdline" "$exe" "$cmd"
  fi
  # [kworker/0:1] 처럼 대괄호 이름인데 실행 파일이 있으면 커널 스레드 위장
  if [[ "$cmd" =~ ^\[.*\][[:space:]]*$ ]] && [ -n "$exe" ]; then
    report "$pid" "fake-kernel-thread" "$exe" "$cmd"
  fi
  if [ -r "$p/environ" ] && tr '\0' '\n' < "$p/environ" 2>/dev/null | grep -q '^LD_PRELOAD='; then
    report "$pid" "ld-preload" "$exe" "$(tr '\0' '\n' < "$p/environ" | grep '^LD_PRELOAD=') :: $cmd"
  fi
  # 실행 파일 이름과 comm 이 전혀 다르면 이름 위장 가능성 (인터프리터 제외)
  if [ -n "$exe" ] && [ -n "$comm" ]; then
    base="$(basename "${exe% (deleted)}")"
    case "$base" in
      python*|perl*|ruby*|node|java|bash|sh|dash|zsh|busybox|php*|systemd|snap*|*.so*) ;;
      *)
        if [ "${base:0:4}" != "${comm:0:4}" ] && [[ ! "$cmd" == *"$base"* ]]; then
          report "$pid" "name-mismatch(comm=$comm)" "$exe" "$cmd"
        fi ;;
    esac
  fi
done

# 고CPU
while read -r pid cpu args; do
  report "$pid" "high-cpu(${cpu}%)" "$(readlink "/proc/$pid/exe" 2>/dev/null)" "$args"
done < <(ps -eo pid=,%cpu=,args= 2>/dev/null | awk -v lim="$CPU_LIMIT" '$2+0 >= lim')

# 의심 경로 바이너리의 네트워크 소켓
if command -v ss >/dev/null 2>&1; then
  while IFS= read -r line; do
    pid="$(echo "$line" | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)"
    [ -n "$pid" ] || continue
    exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
    if [[ "$exe" =~ $TMP_PATHS ]] || [[ "$exe" == *" (deleted)" ]] || [[ "$exe" == /memfd:* ]]; then
      report "$pid" "network-from-susp-binary" "$exe" "$(echo "$line" | awk '{print $1, $4, $5}')"
    fi
  done < <(ss -tanup 2>/dev/null | tail -n +2)
fi

echo
FINDINGS=$(wc -l < "$COUNT_FILE" | tr -d ' ')
if [ "$FINDINGS" -gt 0 ]; then
  echo "[!] 의심 항목 ${FINDINGS}건 — 메모리 덤프(gcore /proc/<pid>/mem) 및 exe 복사 후 조치 검토"
  echo "    삭제된 실행 파일 복구: cp /proc/<pid>/exe ./recovered_<pid>.bin"
  exit 2
fi
echo "[+] 의심 프로세스 없음"
exit 0
