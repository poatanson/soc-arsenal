# SOC Arsenal

SOC 분석가가 일상적으로 쓰는 **로그 헌팅 · IOC/위협 인텔 · 침해사고 대응 · 네트워크/피싱 분석** 자동화 스크립트 모음입니다.

- **설치할 것 없음** — Python 스크립트는 Python 3.9 이상 표준 라이브러리만 사용합니다 (`.evtx` 직접 파싱만 `python-evtx` 선택 설치).
- **공통 CLI 규칙** — 모든 스크립트는 `-h/--help`를 지원하고, 파일 인자가 없으면 stdin을 읽으며, `.gz`는 자동으로 풀어서 읽습니다. 출력은 `--json` / `--csv`로 바꿀 수 있습니다.
- **종료 코드** — `0` 탐지 없음 · `1` 오류 · `2` 탐지 있음 → cron이나 SOAR에서 분기 처리에 쓸 수 있습니다.
- **외부 API는 선택** — VirusTotal / AbuseIPDB / urlscan 키가 있으면 사용하고, 없으면 오프라인 기능만 동작합니다.

```
soc-arsenal/
├── lib/                 공통 모듈 (IOC 정규식·defang, 출력 포맷, TI API 클라이언트)
├── log_hunting/         로그 분석·헌팅
├── ioc_intel/           IOC 추출·변환·평판 조회
├── incident_response/   침해사고 초동 대응 (Linux)
├── network_phishing/    PCAP·메일·DNS·유사 도메인
├── samples/             테스트용 합성 데이터 (모두 가짜)
└── tests/               unittest 테스트
```

## 빠른 시작

```bash
cp .env.example .env          # (선택) API 키 입력
python -m unittest discover -s tests    # 동작 확인 (pytest 로도 실행 가능)

# 샘플로 바로 체험
python log_hunting/ssh_bruteforce.py samples/auth.log
python network_phishing/eml_analyzer.py samples/phishing.eml
python network_phishing/dns_beacon_detect.py samples/dns.log
```

---

## 🔎 log_hunting — 로그 분석·헌팅

| 스크립트 | 용도 | 주요 탐지 |
|---|---|---|
| `ssh_bruteforce.py` | auth.log / secure / journalctl | 무차별 대입, 패스워드 스프레이, **공격 IP의 로그인 성공(침해 의심)** |
| `web_attack_hunter.py` | Apache/Nginx 접근 로그 | SQLi, XSS, LFI, RCE, Log4Shell, SSTI, 웹셸, 민감 파일 탐색, 스캐너 UA |
| `evtx_hunter.py` | Windows 이벤트 로그 (.evtx / XML) | 4625 무차별 대입, 실패 후 로그인 성공, 의심 명령줄(4688/Sysmon 1), 계정 생성·관리자 그룹 추가, 서비스 설치, 예약 작업, 로그 삭제 |
| `log_timeline.sh` | 여러 로그를 하나로 합치기 | syslog / ISO8601 / Apache / epoch(Zeek) 시각을 정규화해 시간순으로 병합 |

```bash
python log_hunting/ssh_bruteforce.py /var/log/auth.log* --threshold 5
python log_hunting/web_attack_hunter.py /var/log/nginx/access.log* --summary
python log_hunting/web_attack_hunter.py access.log --category sqli,rce --success-only
python log_hunting/evtx_hunter.py Security.evtx System.evtx --min-severity high
wevtutil qe Security /f:xml /e:Events > security.xml && python log_hunting/evtx_hunter.py security.xml

# 공격 IP 하나를 기준으로 전체 로그 타임라인 재구성
bash log_hunting/log_timeline.sh -y 2026 -g '203\.0\.113\.50' /var/log/auth.log /var/log/nginx/access.log
bash log_hunting/log_timeline.sh -s "2026-09-26 03:00" -e "2026-09-26 04" *.log -o timeline.tsv
```

## 🧪 ioc_intel — IOC 추출·변환·평판 조회

| 스크립트 | 용도 |
|---|---|
| `ioc_extract.py` | 보고서·메일·HTML·로그에서 IP/도메인/URL/이메일/해시/CVE 추출 (defang 표기 자동 복원, 파일명 오탐 제거) |
| `defang.py` | defang ↔ refang 변환 (`http://evil.com` ↔ `hxxp[://]evil[.]com`) |
| `ioc_enrich.py` | VirusTotal · AbuseIPDB · urlscan 평판 조회 + malicious/suspicious/clean 판정 (24시간 캐시, 무료 한도 준수) |
| `hash_lookup.sh` | 파일/디렉터리 MD5·SHA1·SHA256 계산 → CSV, `-v`로 VirusTotal 조회 |

```bash
python ioc_intel/ioc_extract.py report.pdf.txt --public-only
python ioc_intel/ioc_extract.py report.txt --defang --csv > iocs_for_ticket.csv

# 추출 → 평판 조회 파이프라인
python ioc_intel/ioc_extract.py report.txt --plain --public-only --types ipv4,domain,sha256 \
  | python ioc_intel/ioc_enrich.py --csv > enriched.csv

python ioc_intel/defang.py "http://evil.com/a.php"          # → hxxp[://]evil[.]com/a.php
bash ioc_intel/hash_lookup.sh -r -v ./suspicious_dir -o hashes.csv
```

**판정 기준** (`ioc_enrich.py`): VT 악성 탐지 3개 이상 또는 AbuseIPDB 75점 이상이면 `malicious`, VT 악성·의심 1개 이상 또는 AbuseIPDB 25점 이상이면 `suspicious`. 사설 IP는 조회하지 않습니다.

## 🚨 incident_response — 침해사고 초동 대응

| 스크립트 | 용도 |
|---|---|
| `linux_triage.sh` | 라이브 아티팩트 수집 (시스템·사용자·프로세스·네트워크·지속성·최근 변경 파일·SUID·셸 히스토리·로그) → `tar.gz` + SHA256 매니페스트 |
| `persistence_check.sh` | 지속성 점검: cron/at, systemd, rc.local, 셸 rc, SSH 키, ld.so.preload, UID 0, NOPASSWD, SUID(GTFOBins), PAM, udev, motd, XDG autostart |
| `suspicious_proc.sh` | 의심 프로세스 탐지: 삭제된 실행 파일, memfd(파일리스), 임시 경로 실행, 리버스 셸, 커널 스레드 위장, LD_PRELOAD, 채굴기, 고CPU |
| `file_hash_scan.py` | 디렉터리 해시 스캔 → 악성 해시 목록 대조 / 기준선(baseline) 대비 추가·변경·삭제 탐지 (Windows에서도 동작) |

```bash
sudo bash incident_response/suspicious_proc.sh -v
sudo bash incident_response/persistence_check.sh -d 14
sudo bash incident_response/linux_triage.sh -o /mnt/usb -d 7

python incident_response/file_hash_scan.py /tmp /var/tmp /dev/shm -k known_bad.txt -k misp_export.csv
python incident_response/file_hash_scan.py /var/www --manifest > www_baseline.csv   # 평시에 기준선 생성
python incident_response/file_hash_scan.py /var/www --baseline www_baseline.csv     # 사고 시 비교 (웹셸 탐지)
```

> ⚠️ **IR 주의사항**
> - 수집 스크립트는 시스템을 변경하지 않지만, 실행 자체가 흔적(메모리·atime)을 남깁니다. 메모리 포렌식이 필요하면 **먼저 메모리 덤프**(LiME/AVML)를 뜨세요.
> - 루트킷이 있으면 `ps`/`ss` 같은 시스템 바이너리가 변조되어 있을 수 있습니다. 신뢰할 수 있는 정적 바이너리 경로를 `TRUSTED_BIN=/mnt/usb/bin`으로 지정하면 PATH 맨 앞에 둡니다.
> - 결과는 가능하면 외부 저장소(`-o /mnt/usb`)에 저장하세요.

## 🌐 network_phishing — 네트워크·피싱

| 스크립트 | 용도 |
|---|---|
| `eml_analyzer.py` | .eml 분석: Received 경로와 최초 발신 IP, SPF/DKIM/DMARC, 표시 이름 위장, Reply-To 불일치, 링크 텍스트와 실제 URL 불일치, 첨부파일 해시, 위험·이중 확장자 |
| `pcap_summary.py` | PCAP/PCAPNG 요약: 상위 대화, DNS 질의, HTTP 요청, TLS SNI, 비표준 포트 (의존성 없음) |
| `typosquat_gen.py` | 유사 도메인 생성(14가지 기법, IDN 호모글리프 포함) + `--resolve`로 등록 여부 확인 + `--check`로 로그에서 사칭 도메인 찾기 |
| `dns_beacon_detect.py` | DNS 로그(Zeek TSV/JSON, dnsmasq, 일반 텍스트)에서 C2 비커닝(간격 변동계수), DGA(엔트로피 점수), DNS 터널링 탐지 |

```bash
python network_phishing/eml_analyzer.py suspicious.eml -x ./quarantine    # 첨부파일은 .quarantine 확장자로 저장
python network_phishing/pcap_summary.py capture.pcapng --top 20
python network_phishing/typosquat_gen.py mybank.co.kr --resolve --registered-only
python ioc_intel/ioc_extract.py proxy.log --plain --types domain \
  | python network_phishing/typosquat_gen.py mybank.co.kr --check -
python network_phishing/dns_beacon_detect.py /opt/zeek/logs/current/dns.log --allowlist allow.txt
```

---

## 샘플 데이터

`samples/`의 모든 데이터는 테스트용으로 **만들어낸 가짜**입니다. IP는 문서용 대역(RFC 5737)과 사설 대역을 주로 쓰며, 악성 파일은 없습니다(`evidence/dropper_stub.bin`은 평범한 텍스트입니다).
`dns.log`와 `sample.pcap`은 `python samples/generate_samples.py`로 다시 만들 수 있습니다.

## 새 스크립트 추가 규칙

1. 스크립트 맨 위에 `sys.path.insert(0, 저장소 루트)`를 두고 `lib.cli` / `lib.output` / `lib.ioc_patterns`를 재사용합니다.
2. docstring에 용도·탐지 기준·예시를 적습니다 (`--help`에 그대로 나옵니다).
3. `add_output_args()`로 `--json`/`--csv`를 지원하고, 종료 코드 규칙(0/1/2)을 지킵니다.
4. `samples/`에 합성 데이터를, `tests/`에 탐지·비탐지 케이스를 추가합니다.
