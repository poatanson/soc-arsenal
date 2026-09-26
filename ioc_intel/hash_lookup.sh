#!/usr/bin/env bash
# hash_lookup.sh - 파일/디렉터리의 MD5·SHA1·SHA256 해시를 계산하고, 선택적으로 VirusTotal 조회
#
# 사용법:
#   hash_lookup.sh [-r] [-v] [-o out.csv] <파일|디렉터리>...
#     -r  디렉터리 재귀 탐색
#     -v  VirusTotal 조회 (VT_API_KEY 필요, 무료 한도 때문에 요청 간 15초 대기)
#     -o  CSV 파일로 저장 (기본: stdout)
#
# 출력(CSV): path,size,md5,sha1,sha256[,vt_malicious,vt_total,vt_link]
# 종료 코드: 0=정상, 1=오류, 2=VT에서 악성 탐지(malicious>0) 존재
set -euo pipefail

usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

RECURSIVE=0
VT=0
OUT=""
while getopts ":rvo:h" opt; do
  case "$opt" in
    r) RECURSIVE=1 ;;
    v) VT=1 ;;
    o) OUT="$OPTARG" ;;
    h) usage 0 ;;
    *) usage 1 ;;
  esac
done
shift $((OPTIND - 1))
[ $# -ge 1 ] || usage 1

# 저장소 루트의 .env 에서 VT_API_KEY 로드 (이미 설정된 값 우선)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -z "${VT_API_KEY:-}" ] && [ -f "$SCRIPT_DIR/../.env" ]; then
  VT_API_KEY="$(grep -E '^VT_API_KEY=' "$SCRIPT_DIR/../.env" | head -1 | cut -d= -f2- | tr -d "\"' \r")"
fi
if [ "$VT" -eq 1 ] && [ -z "${VT_API_KEY:-}" ]; then
  echo "[!] VT_API_KEY 가 없어 VirusTotal 조회를 건너뜁니다" >&2
  VT=0
fi
if [ "$VT" -eq 1 ] && ! command -v curl >/dev/null 2>&1; then
  echo "[-] VirusTotal 조회에는 curl 이 필요합니다" >&2
  exit 1
fi

# 해시 명령 선택 (Linux: *sum, macOS: shasum/md5)
hash_of() {
  local algo="$1" file="$2"
  case "$algo" in
    md5)
      if command -v md5sum >/dev/null 2>&1; then md5sum "$file" | awk '{print $1}'
      else md5 -q "$file"; fi ;;
    sha1)
      if command -v sha1sum >/dev/null 2>&1; then sha1sum "$file" | awk '{print $1}'
      else shasum -a 1 "$file" | awk '{print $1}'; fi ;;
    sha256)
      if command -v sha256sum >/dev/null 2>&1; then sha256sum "$file" | awk '{print $1}'
      else shasum -a 256 "$file" | awk '{print $1}'; fi ;;
  esac
}

file_size() { wc -c < "$1" | tr -d ' '; }

# VT 응답 JSON에서 last_analysis_stats 추출 → "malicious total"
parse_vt() {
  if command -v jq >/dev/null 2>&1; then
    jq -r '.data.attributes.last_analysis_stats // empty
           | "\(.malicious) \(.malicious + .suspicious + .harmless + .undetected)"'
  elif command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1; then
    "$(command -v python3 || command -v python)" -c '
import json, sys
try:
    s = json.load(sys.stdin)["data"]["attributes"]["last_analysis_stats"]
    print(s["malicious"], s["malicious"] + s["suspicious"] + s["harmless"] + s["undetected"])
except Exception:
    pass'
  else
    echo "[-] VT 응답 파싱에 jq 또는 python 이 필요합니다" >&2
  fi
}

VT_LAST=0
vt_lookup() {
  local sha256="$1" now wait body code
  now=$(date +%s)
  wait=$((15 - (now - VT_LAST)))
  if [ "$VT_LAST" -ne 0 ] && [ "$wait" -gt 0 ]; then sleep "$wait"; fi
  VT_LAST=$(date +%s)
  body="$(mktemp)"
  code=$(curl -s -o "$body" -w '%{http_code}' -H "x-apikey: $VT_API_KEY" \
    "https://www.virustotal.com/api/v3/files/$sha256" || echo "000")
  case "$code" in
    200) parse_vt < "$body" ;;
    404) echo "not_found -" ;;
    429) echo "rate_limited -" ;;
    *)   echo "error_$code -" ;;
  esac
  rm -f "$body"
}

collect_files() {
  local target
  for target in "$@"; do
    if [ -f "$target" ]; then
      printf '%s\n' "$target"
    elif [ -d "$target" ]; then
      if [ "$RECURSIVE" -eq 1 ]; then
        find "$target" -type f 2>/dev/null
      else
        find "$target" -maxdepth 1 -type f 2>/dev/null
      fi
    else
      echo "[!] 존재하지 않음: $target" >&2
    fi
  done
}

csv_escape() { local s="${1//\"/\"\"}"; printf '"%s"' "$s"; }

run() {
  local detected=0 f md5 sha1 sha256 size result mal total
  if [ "$VT" -eq 1 ]; then
    echo "path,size,md5,sha1,sha256,vt_malicious,vt_total,vt_link"
  else
    echo "path,size,md5,sha1,sha256"
  fi
  while IFS= read -r f; do
    [ -r "$f" ] || { echo "[!] 읽기 불가: $f" >&2; continue; }
    size=$(file_size "$f")
    md5=$(hash_of md5 "$f")
    sha1=$(hash_of sha1 "$f")
    sha256=$(hash_of sha256 "$f")
    if [ "$VT" -eq 1 ]; then
      echo "[*] VT 조회: $f" >&2
      result="$(vt_lookup "$sha256")"
      mal="${result%% *}"
      total="${result#* }"
      if [[ "$mal" =~ ^[0-9]+$ ]] && [ "$mal" -gt 0 ]; then
        detected=1
        echo "[!] 악성 탐지 $mal/$total: $f" >&2
      fi
      printf '%s,%s,%s,%s,%s,%s,%s,%s\n' "$(csv_escape "$f")" "$size" "$md5" "$sha1" "$sha256" \
        "$mal" "$total" "https://www.virustotal.com/gui/file/$sha256"
    else
      printf '%s,%s,%s,%s,%s\n' "$(csv_escape "$f")" "$size" "$md5" "$sha1" "$sha256"
    fi
  done < <(collect_files "$@")
  return "$detected"
}

status=0
if [ -n "$OUT" ]; then
  run "$@" > "$OUT" || status=$?
  echo "[*] 저장: $OUT" >&2
else
  run "$@" || status=$?
fi
[ "$status" -eq 1 ] && exit 2
exit 0
