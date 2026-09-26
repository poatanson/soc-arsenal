#!/usr/bin/env bash
# linux_triage.sh - Linux 침해사고 초동 대응용 라이브 아티팩트 수집 (읽기 전용)
#
# 사용법:
#   sudo linux_triage.sh [-o 출력디렉터리] [-d 일수] [-n] [-q]
#     -o  결과 저장 위치 (기본: 현재 디렉터리). 가능하면 외부 USB/네트워크 공유를 지정
#     -d  최근 변경 파일 탐색 기간(일) (기본: 3)
#     -n  로그 파일 복사 생략 (/var/log)
#     -q  진행 메시지 숨김
#
# 수집 항목: 시스템 정보, 사용자/로그인, 프로세스, 네트워크, 지속성(cron/systemd/rc/ssh키),
#           최근 변경 파일, SUID, 셸 히스토리, 주요 로그
# 결과: triage_<호스트>_<UTC시각>/ + .tar.gz + SHA256 매니페스트
#
# 주의:
#  - 시스템을 변경하지 않지만, 실행 자체가 메모리/타임스탬프(atime)에 흔적을 남긴다.
#    메모리 포렌식이 필요하면 이 스크립트보다 먼저 메모리 덤프(LiME/AVML)를 뜰 것.
#  - 루트킷 감염 시 ps/ss 등 시스템 바이너리가 변조되었을 수 있다.
#    신뢰할 수 있는 정적 바이너리 경로를 TRUSTED_BIN 환경변수로 지정하면 PATH 앞에 둔다.
set -euo pipefail

usage() { sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

OUT_BASE="."
DAYS=3
SKIP_LOGS=0
QUIET=0
while getopts ":o:d:nqh" opt; do
  case "$opt" in
    o) OUT_BASE="$OPTARG" ;;
    d) DAYS="$OPTARG" ;;
    n) SKIP_LOGS=1 ;;
    q) QUIET=1 ;;
    h) usage 0 ;;
    *) usage 1 ;;
  esac
done

if [ -n "${TRUSTED_BIN:-}" ]; then
  export PATH="$TRUSTED_BIN:$PATH"
fi
export LC_ALL=C

if [ "$(id -u)" -ne 0 ]; then
  echo "[!] root 가 아닙니다. 일부 항목(/etc/shadow, 다른 사용자 파일, 프로세스 상세)이 누락됩니다." >&2
fi

HOST="$(hostname 2>/dev/null || cat /etc/hostname)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$OUT_BASE/triage_${HOST}_${STAMP}"
mkdir -p "$OUT"/{system,users,processes,network,persistence,files,logs,history}
ERRLOG="$OUT/collection_errors.log"
: > "$ERRLOG"

log() { [ "$QUIET" -eq 1 ] || echo "[*] $*" >&2; }

# run <출력파일> <명령...>  : 명령이 없거나 실패해도 계속 진행
run() {
  local out="$1"; shift
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing command: $1" >> "$ERRLOG"
    return 0
  fi
  { echo "# $(date -u +%FT%TZ) \$ $*"; "$@"; } > "$OUT/$out" 2>> "$ERRLOG" || echo "failed($?): $*" >> "$ERRLOG"
}

# copy <대상디렉터리> <파일...> : 존재하는 파일만 메타데이터 유지 복사
copy() {
  local dest="$OUT/$1"; shift
  local f
  mkdir -p "$dest"
  for f in "$@"; do
    [ -e "$f" ] || continue
    cp -a --parents "$f" "$dest" 2>> "$ERRLOG" || cp -p "$f" "$dest" 2>> "$ERRLOG" || true
  done
}

# 사용자 홈 디렉터리 목록 (/etc/passwd 기준)
homes() { [ -r /etc/passwd ] || return 0; awk -F: '$6 ~ /^\// {print $1":"$6}' /etc/passwd | sort -u; }

# ---------------------------------------------------------------- 시스템
log "시스템 정보"
{
  echo "collected_at_utc: $STAMP"
  echo "hostname: $HOST"
  echo "collector_uid: $(id -u) ($(id -un))"
  echo "local_time: $(date)"
  echo "timezone: $(cat /etc/timezone 2>/dev/null || readlink /etc/localtime 2>/dev/null || echo unknown)"
} > "$OUT/system/collection_info.txt"
run system/uname.txt uname -a
run system/os-release.txt cat /etc/os-release
run system/uptime.txt uptime
run system/df.txt df -h
run system/mount.txt mount
run system/lsmod.txt lsmod
run system/env.txt env
run system/dmesg_tail.txt sh -c 'dmesg 2>/dev/null | tail -n 300'
run system/packages_recent.txt sh -c 'if [ -d /var/lib/dpkg/info ]; then ls -lt --time-style=full-iso /var/lib/dpkg/info/*.list | head -50; else rpm -qa --last | head -50; fi'

# ---------------------------------------------------------------- 사용자
log "사용자/로그인"
copy users /etc/passwd /etc/group /etc/shadow /etc/sudoers /etc/sudoers.d
run users/uid0.txt awk -F: '$3 == 0 {print}' /etc/passwd
run users/who.txt who -a
run users/w.txt w
run users/last.txt sh -c 'last -Faiw 2>/dev/null | head -500 || last | head -500'
run users/lastb.txt sh -c 'lastb -Faiw 2>/dev/null | head -500'
run users/lastlog.txt lastlog
run users/logged_in_sessions.txt loginctl list-sessions --no-pager

# ---------------------------------------------------------------- 프로세스
log "프로세스"
run processes/ps_tree.txt ps auxwwf
run processes/ps_full.txt ps -eo pid,ppid,user,lstart,etime,stat,args --sort=pid
run processes/top_cpu.txt sh -c 'ps -eo pid,user,%cpu,%mem,args --sort=-%cpu | head -30'
{
  echo "pid|exe|cwd|cmdline"
  for p in /proc/[0-9]*; do
    pid="${p#/proc/}"
    exe="$(readlink "$p/exe" 2>/dev/null || echo '-')"
    cwd="$(readlink "$p/cwd" 2>/dev/null || echo '-')"
    cmd="$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null || true)"
    echo "$pid|$exe|$cwd|$cmd"
  done
} > "$OUT/processes/proc_exe_cwd.txt" 2>> "$ERRLOG"
grep -E '\(deleted\)|\|/tmp/|\|/var/tmp/|\|/dev/shm/|memfd:' "$OUT/processes/proc_exe_cwd.txt" \
  > "$OUT/processes/SUSPICIOUS_exe_locations.txt" 2>/dev/null || true
run processes/open_files_net.txt lsof -nP -i

# ---------------------------------------------------------------- 네트워크
log "네트워크"
if command -v ss >/dev/null 2>&1; then
  run network/connections.txt ss -tanup
  run network/listening.txt ss -tulpn
else
  run network/connections.txt netstat -tanup
  run network/listening.txt netstat -tulpn
fi
run network/ip_addr.txt ip addr
run network/ip_route.txt ip route
run network/arp.txt ip neigh
run network/iptables.txt iptables-save
run network/nft.txt nft list ruleset
copy network /etc/hosts /etc/resolv.conf /etc/hosts.allow /etc/hosts.deny

# ---------------------------------------------------------------- 지속성
log "지속성(persistence)"
copy persistence /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly \
  /var/spool/cron /etc/anacrontab /etc/rc.local /etc/ld.so.preload /etc/profile /etc/profile.d \
  /etc/bash.bashrc /etc/bashrc /etc/environment /etc/update-motd.d /etc/pam.d /etc/ssh/sshd_config \
  /etc/systemd/system /etc/udev/rules.d /etc/xdg/autostart
run persistence/systemd_enabled.txt systemctl list-unit-files --state=enabled --no-pager
run persistence/systemd_running.txt systemctl list-units --type=service --state=running --no-pager
run persistence/systemd_timers.txt systemctl list-timers --all --no-pager
run persistence/at_jobs.txt atq
while IFS=: read -r user home; do
  for f in .ssh/authorized_keys .ssh/authorized_keys2 .bashrc .bash_profile .profile .zshrc .config/autostart \
           .config/systemd/user; do
    if [ -e "$home/$f" ]; then copy "persistence/home_$user" "$home/$f"; fi
  done
  crontab -l -u "$user" > "$OUT/persistence/crontab_$user.txt" 2>/dev/null || rm -f "$OUT/persistence/crontab_$user.txt"
done < <(homes)

# ---------------------------------------------------------------- 파일
log "최근 ${DAYS}일 변경 파일 / SUID"
run files/recent_modified.txt find /etc /tmp /var/tmp /dev/shm /root /home /usr/bin /usr/sbin /bin /sbin \
  /usr/local /opt /var/www -xdev -type f -mtime "-$DAYS" -printf '%TY-%Tm-%Td %TH:%TM %u %m %s %p\n'
run files/tmp_listing.txt ls -laR --time-style=full-iso /tmp /var/tmp /dev/shm
run files/hidden_in_tmp.txt find /tmp /var/tmp /dev/shm -name '.*' -printf '%TY-%Tm-%Td %TH:%TM %u %m %s %p\n'
run files/executables_in_tmp.txt find /tmp /var/tmp /dev/shm -type f -perm -u+x -printf '%TY-%Tm-%Td %TH:%TM %u %m %s %p\n'
run files/suid_sgid.txt find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf '%TY-%Tm-%Td %u %m %p\n'
run files/web_scripts_recent.txt find /var/www /srv /usr/share/nginx -type f \
  \( -name '*.php' -o -name '*.jsp' -o -name '*.asp*' -o -name '*.py' \) -mtime "-$DAYS" -printf '%TY-%Tm-%Td %TH:%TM %u %p\n'

# ---------------------------------------------------------------- 셸 히스토리
log "셸 히스토리"
while IFS=: read -r user home; do
  for f in .bash_history .zsh_history .sh_history .python_history .mysql_history .psql_history .lesshst .viminfo; do
    if [ -f "$home/$f" ]; then copy "history/$user" "$home/$f"; fi
  done
done < <(homes)

# ---------------------------------------------------------------- 로그
if [ "$SKIP_LOGS" -eq 0 ]; then
  log "로그 복사"
  copy logs /var/log/auth.log* /var/log/secure* /var/log/syslog* /var/log/messages* /var/log/kern.log* \
    /var/log/audit /var/log/cron* /var/log/wtmp /var/log/btmp /var/log/lastlog /var/log/nginx /var/log/apache2 \
    /var/log/httpd
  run logs/journal_24h.txt journalctl --since "-24h" --no-pager -o short-iso
fi

# ---------------------------------------------------------------- 패키징
log "매니페스트/압축"
( cd "$OUT" && find . -type f ! -name MANIFEST.sha256 -exec sha256sum {} + > MANIFEST.sha256 ) 2>> "$ERRLOG" || true
tar -czf "$OUT.tar.gz" -C "$(dirname "$OUT")" "$(basename "$OUT")" 2>> "$ERRLOG" || true
if [ -f "$OUT.tar.gz" ]; then
  ( cd "$(dirname "$OUT")" && sha256sum "$(basename "$OUT").tar.gz" > "$(basename "$OUT").tar.gz.sha256" )
  echo "[+] 완료: $OUT.tar.gz"
  cat "$OUT.tar.gz.sha256"
else
  echo "[+] 완료: $OUT (압축 실패, 디렉터리 확인)"
fi
if [ -s "$OUT/processes/SUSPICIOUS_exe_locations.txt" ]; then
  echo "[!] 의심 위치에서 실행 중인 프로세스 발견: $OUT/processes/SUSPICIOUS_exe_locations.txt" >&2
fi
