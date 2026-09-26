#!/usr/bin/env bash
# persistence_check.sh - Linux 지속성(persistence) 메커니즘 점검 (읽기 전용)
#
# 사용법:
#   sudo persistence_check.sh [-d 일수] [-v]
#     -d  "최근 변경"으로 볼 기간(일) (기본: 7)
#     -v  의심 항목이 아닌 정보성 항목도 출력
#
# 점검 항목 (MITRE ATT&CK):
#   cron/at (T1053) · systemd 서비스/타이머 (T1543.002) · rc.local/init.d (T1037)
#   셸 초기화 파일 (T1546.004) · SSH authorized_keys (T1098.004) · ld.so.preload (T1574.006)
#   UID 0 계정/빈 패스워드 (T1136) · sudoers NOPASSWD · SUID/SGID (T1548.001)
#   PAM 모듈 (T1556.003) · udev 규칙 · update-motd · XDG autostart
# 종료 코드: 0=의심 항목 없음, 2=의심 항목 있음
set -uo pipefail

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

DAYS=7
VERBOSE=0
while getopts ":d:vh" opt; do
  case "$opt" in
    d) DAYS="$OPTARG" ;;
    v) VERBOSE=1 ;;
    h) usage 0 ;;
    *) usage 1 ;;
  esac
done
export LC_ALL=C

[ "$(id -u)" -eq 0 ] || echo "[!] root 권한이 아니면 일부 항목을 확인할 수 없습니다" >&2

# flag 는 파이프라인(서브셸) 안에서도 호출되므로 카운트를 파일로 집계한다
COUNT_FILE="$(mktemp)"
trap 'rm -f "$COUNT_FILE"' EXIT
# 명령줄에서 흔한 악성 패턴
SUSP='(curl|wget)[^|;]*\|[[:space:]]*(ba)?sh|/dev/tcp/|/dev/udp/|bash -i|sh -i|nc(at)? .*-e|socat .*exec|mkfifo|base64 (-d|--decode)|python[23]? -c|perl -e|php -r|/tmp/|/var/tmp/|/dev/shm/|chmod \+x|xmrig|stratum\+tcp|LD_PRELOAD|nohup .*&'

if [ -t 1 ]; then RED=$'\033[31m'; RST=$'\033[0m'; else RED=""; RST=""; fi
flag() { echo x >> "$COUNT_FILE"; printf '%s[!]%s %-14s %s\n' "$RED" "$RST" "$1" "$2"; }
note() { [ "$VERBOSE" -eq 1 ] && printf '[i] %-14s %s\n' "$1" "$2"; return 0; }
section() { printf '\n=== %s ===\n' "$1"; }

# 파일 내용에서 의심 패턴 검색 (주석 제외)
scan_file() {
  local tag="$1" file="$2" line
  [ -r "$file" ] || return 0
  while IFS= read -r line; do
    flag "$tag" "$file: $line"
  done < <(grep -Ev '^[[:space:]]*#' "$file" 2>/dev/null | grep -Ei -- "$SUSP" || true)
}

recent() { find "$@" -xdev -mtime "-$DAYS" 2>/dev/null; }

homes() { [ -r /etc/passwd ] || return 0; awk -F: '$6 ~ /^\// {print $1":"$6}' /etc/passwd | sort -u; }

# ------------------------------------------------------------ cron / at
section "cron / at"
for f in /etc/crontab /etc/anacrontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* \
         /etc/cron.weekly/* /etc/cron.monthly/* /var/spool/cron/* /var/spool/cron/crontabs/*; do
  [ -f "$f" ] || continue
  scan_file "cron" "$f"
  note "cron" "$f"
done
while IFS= read -r f; do flag "cron-recent" "최근 ${DAYS}일 내 변경: $f"; done \
  < <(recent /etc/cron* /var/spool/cron -type f)
if command -v atq >/dev/null 2>&1 && [ -n "$(atq 2>/dev/null)" ]; then
  flag "at-job" "예약된 at 작업 존재: $(atq | tr '\n' ' ')"
fi

# ------------------------------------------------------------ systemd
section "systemd 서비스 / 타이머"
UNIT_DIRS="/etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /run/systemd/system"
while IFS=: read -r _ home; do UNIT_DIRS="$UNIT_DIRS $home/.config/systemd/user"; done < <(homes)
for d in $UNIT_DIRS; do
  [ -d "$d" ] || continue
  while IFS= read -r unit; do
    while IFS= read -r line; do
      flag "systemd" "$unit: $line"
    done < <(grep -E '^[[:space:]]*Exec(Start|StartPre|StartPost|Stop|Reload)=' "$unit" 2>/dev/null | grep -Ei -- "$SUSP" || true)
  done < <(find "$d" -maxdepth 2 -type f \( -name '*.service' -o -name '*.timer' \) 2>/dev/null)
  while IFS= read -r unit; do
    flag "systemd-recent" "최근 ${DAYS}일 내 변경: $unit"
  done < <(recent "$d" -type f \( -name '*.service' -o -name '*.timer' \))
done

# ------------------------------------------------------------ rc / init
section "rc.local / init.d"
if [ -f /etc/rc.local ]; then
  body="$(grep -Ev '^[[:space:]]*(#|$|exit 0)' /etc/rc.local 2>/dev/null || true)"
  if [ -n "$body" ]; then
    flag "rc.local" "내용 있음: $(echo "$body" | tr '\n' ';' | cut -c1-200)"
  fi
fi
while IFS= read -r f; do flag "init.d-recent" "최근 ${DAYS}일 내 변경: $f"; done < <(recent /etc/init.d -type f)

# ------------------------------------------------------------ shell rc
section "셸 초기화 파일"
RC_FILES="/etc/profile /etc/bash.bashrc /etc/bashrc /etc/zshrc /etc/environment"
for f in /etc/profile.d/*; do RC_FILES="$RC_FILES $f"; done
while IFS=: read -r _ home; do
  RC_FILES="$RC_FILES $home/.bashrc $home/.bash_profile $home/.bash_login $home/.profile $home/.zshrc $home/.bash_logout"
done < <(homes)
for f in $RC_FILES; do
  [ -f "$f" ] || continue
  scan_file "shell-rc" "$f"
  # alias ls='ls --color' 처럼 같은 명령에 옵션만 붙인 건 정상
  # → 다른 명령으로 바꿔치기했거나 grep -v 로 결과를 숨기는 경우만 탐지
  while IFS= read -r line; do
    flag "shell-alias" "$f: 민감 명령을 다른 명령으로 alias: $line"
  done < <(grep -E '^[[:space:]]*alias[[:space:]]+(sudo|ssh|su|ls|ps|netstat|ss|passwd|top|lsof)=' "$f" 2>/dev/null \
    | awk '{
        s = $0; sub(/^[ \t]*alias[ \t]+/, "", s)
        name = s; sub(/=.*/, "", name)
        val = s; sub(/^[^=]*=/, "", val); gsub(/["\047]/, "", val)
        split(val, w, /[ \t]+/)
        if ((w[1] != name && w[1] != "command" && w[1] != "\\" name) || val ~ /grep[ \t]+-v/) print
      }')
  if [ -n "$(find "$f" -mtime "-$DAYS" 2>/dev/null)" ]; then flag "shell-rc-recent" "최근 ${DAYS}일 내 변경: $f"; fi
done

# ------------------------------------------------------------ SSH
section "SSH authorized_keys / sshd_config"
while IFS=: read -r user home; do
  for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
    [ -f "$f" ] || continue
    n=$(grep -cEv '^[[:space:]]*(#|$)' "$f" 2>/dev/null || echo 0)
    note "ssh-keys" "$user: $f ($n keys)"
    if [ -n "$(find "$f" -mtime "-$DAYS" 2>/dev/null)" ]; then flag "ssh-key-recent" "$user: 최근 ${DAYS}일 내 변경 $f ($n keys)"; fi
    if grep -Eq '(^|,)command=' "$f" 2>/dev/null; then flag "ssh-key-cmd" "$user: command= 옵션이 있는 키 ($f)"; fi
    if [ "$user" = "root" ] && [ "$n" -gt 0 ]; then note "ssh-root" "root 에 등록된 키 $n개"; fi
  done
done < <(homes)
if [ -r /etc/ssh/sshd_config ]; then
  grep -Eiq '^[[:space:]]*PermitRootLogin[[:space:]]+yes' /etc/ssh/sshd_config && flag "sshd" "PermitRootLogin yes"
  grep -Eiq '^[[:space:]]*PermitEmptyPasswords[[:space:]]+yes' /etc/ssh/sshd_config && flag "sshd" "PermitEmptyPasswords yes"
  grep -Ei '^[[:space:]]*AuthorizedKeysFile' /etc/ssh/sshd_config | grep -Evq '\.ssh/authorized_keys' \
    && flag "sshd" "비표준 AuthorizedKeysFile: $(grep -Ei '^[[:space:]]*AuthorizedKeysFile' /etc/ssh/sshd_config)"
fi

# ------------------------------------------------------------ 동적 링커
section "ld.so.preload / 동적 링커"
if [ -s /etc/ld.so.preload ]; then
  flag "ld.so.preload" "내용: $(tr '\n' ' ' < /etc/ld.so.preload)  ← 사용자 공간 루트킷 흔한 기법"
fi
grep -rEl 'LD_PRELOAD|LD_LIBRARY_PATH' /etc/environment /etc/profile /etc/profile.d 2>/dev/null \
  | while IFS= read -r f; do flag "ld-env" "$f 에서 LD_PRELOAD/LD_LIBRARY_PATH 설정"; done
while IFS= read -r f; do flag "ld.so.conf" "최근 ${DAYS}일 내 변경: $f"; done < <(recent /etc/ld.so.conf /etc/ld.so.conf.d -type f)

# ------------------------------------------------------------ 계정
section "계정 / sudo"
awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd | while IFS= read -r u; do
  flag "uid0" "root 외 UID 0 계정: $u"
done
if [ -r /etc/shadow ]; then
  awk -F: '$2 == "" {print $1}' /etc/shadow | while IFS= read -r u; do flag "empty-pw" "빈 패스워드 계정: $u"; done
fi
awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ && $3 < 1000 && $1 != "root" {print $1" ("$7")"}' /etc/passwd \
  | while IFS= read -r u; do flag "sys-shell" "로그인 셸을 가진 시스템 계정: $u"; done
for f in /etc/sudoers /etc/sudoers.d/*; do
  [ -r "$f" ] || continue
  grep -Ev '^[[:space:]]*#' "$f" | grep -E 'NOPASSWD' | while IFS= read -r line; do
    flag "sudo-nopasswd" "$f: $line"
  done
done
while IFS= read -r f; do flag "account-recent" "최근 ${DAYS}일 내 변경: $f"; done \
  < <(recent /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/sudoers.d -type f)

# ------------------------------------------------------------ SUID
section "SUID / SGID"
while IFS= read -r f; do flag "suid-location" "비정상 위치의 SUID/SGID: $f"; done \
  < <(find /tmp /var/tmp /dev/shm /home /root /opt /var/www -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null)
while IFS= read -r f; do flag "suid-recent" "최근 ${DAYS}일 내 변경된 SUID: $f"; done \
  < <(find / -xdev -perm -4000 -type f -mtime "-$DAYS" 2>/dev/null)
for bin in find vim vi nano python python3 perl bash sh less more nmap awk cp env tar zip; do
  p="$(command -v "$bin" 2>/dev/null || true)"
  [ -n "$p" ] && [ -u "$(readlink -f "$p")" ] && flag "suid-gtfobin" "권한 상승 가능 바이너리에 SUID: $p (GTFOBins)"
done

# ------------------------------------------------------------ PAM
section "PAM"
for d in /lib/security /lib64/security /usr/lib/security /usr/lib64/security /lib/x86_64-linux-gnu/security /usr/lib/x86_64-linux-gnu/security; do
  [ -d "$d" ] || continue
  while IFS= read -r f; do flag "pam-module-recent" "최근 ${DAYS}일 내 변경된 PAM 모듈: $f"; done < <(recent "$d" -type f -name '*.so')
done
while IFS= read -r f; do flag "pam-conf-recent" "최근 ${DAYS}일 내 변경: $f"; done < <(recent /etc/pam.d -type f)
grep -rEn 'pam_exec\.so' /etc/pam.d 2>/dev/null | while IFS= read -r line; do flag "pam-exec" "$line"; done

# ------------------------------------------------------------ 기타 자동 실행
section "udev / motd / XDG autostart"
for f in /etc/udev/rules.d/*; do
  [ -f "$f" ] || continue
  grep -Ei 'RUN\+?=' "$f" | grep -Ei -- "$SUSP" | while IFS= read -r line; do flag "udev" "$f: $line"; done
done
for f in /etc/update-motd.d/*; do [ -f "$f" ] && scan_file "motd" "$f"; done
for f in /etc/xdg/autostart/*.desktop; do [ -f "$f" ] && scan_file "xdg-autostart" "$f"; done
while IFS=: read -r _ home; do
  for f in "$home"/.config/autostart/*.desktop; do [ -f "$f" ] && scan_file "xdg-autostart" "$f"; done
done < <(homes)

# ------------------------------------------------------------ 결과
echo
FINDINGS=$(wc -l < "$COUNT_FILE" | tr -d ' ')
if [ "$FINDINGS" -gt 0 ]; then
  echo "[!] 의심 항목 ${FINDINGS}건 — 각 항목을 정상 운영 변경과 대조하세요"
  exit 2
fi
echo "[+] 의심 항목 없음"
exit 0
