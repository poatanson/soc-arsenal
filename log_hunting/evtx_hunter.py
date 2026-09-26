#!/usr/bin/env python3
"""Windows 이벤트 로그 헌팅 (Security / System / Sysmon).

입력:
  *.evtx : python-evtx 필요 (pip install python-evtx)
  *.xml  : 표준 라이브러리만으로 처리
           wevtutil qe Security /f:xml /e:Events > security.xml
           Get-WinEvent ... | ForEach-Object { $_.ToXml() } 결과도 가능

탐지 규칙:
  4625  로그인 실패 집계 → 무차별 대입/스프레이 (IP·계정별)
  4624  원격 로그인(LogonType 3/10) 중 실패가 많았던 IP에서의 성공, RDP(10), NewCredentials(9)
  4688 / Sysmon 1  의심 명령줄 (인코딩된 PowerShell, LOLBin 다운로드 등)
  4720 계정 생성, 4728/4732/4756 관리자 그룹 추가
  7045 / 4697 서비스 설치 (의심 ImagePath 가중)
  4698 예약 작업 생성
  1102 / 104 로그 삭제
종료 코드: 0=탐지 없음, 1=오류, 2=탐지 있음

예시:
  evtx_hunter.py Security.evtx System.evtx
  evtx_hunter.py security.xml --min-severity high
  evtx_hunter.py C:/Windows/System32/winevt/Logs/Security.evtx --csv > findings.csv
"""
import argparse
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterator, List

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib.cli import EXIT_DETECTED, EXIT_OK, add_output_args, check_files_exist, die, setup_stdio, warn  # noqa: E402
from lib.output import emit  # noqa: E402

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

SUSPICIOUS_CMD = [
    ("high", "encoded-powershell", r"powershell.*\s-(?:e|en|enc|encodedcommand)\b\s+[A-Za-z0-9+/=]{16,}"),
    ("high", "download-cradle", r"downloadstring|downloadfile|invoke-webrequest|iwr\s+http|net\.webclient|start-bitstransfer"),
    ("high", "iex", r"\biex\b|invoke-expression"),
    ("high", "certutil-download", r"certutil.*(?:-urlcache|-decode|-encode)"),
    ("high", "lolbin-proxy", r"mshta(?:\.exe)?\s+(?:https?|javascript|vbscript)|rundll32.*javascript:|regsvr32.*/i:https?|bitsadmin.*/transfer"),
    ("high", "credential-dump", r"sekurlsa|lsadump|mimikatz|procdump.*lsass|comsvcs(?:\.dll)?.*minidump|ntdsutil.*ifm|reg(?:\.exe)?\s+save\s+hklm\\(?:sam|system|security)"),
    ("high", "shadow-copy-delete", r"vssadmin.*delete\s+shadows|wmic.*shadowcopy.*delete|wbadmin.*delete\s+catalog|bcdedit.*recoveryenabled\s+no"),
    ("medium", "hidden-window", r"-w(?:indowstyle)?\s+hidden|-nop\b|-noprofile\b.*-ep\s+bypass|-executionpolicy\s+bypass"),
    ("medium", "recon", r"\b(?:whoami\s+/(?:all|priv)|net\s+(?:user|group|localgroup)\s|nltest\s|dsquery|adfind)"),
    ("medium", "defender-tamper", r"set-mppreference.*disable|add-mppreference.*exclusion"),
    ("medium", "persistence-cmd", r"schtasks.*/create|reg(?:\.exe)?\s+add.*\\(?:run|runonce)\b|sc(?:\.exe)?\s+create"),
]
SUSPICIOUS_CMD_RX = [(s, n, re.compile(p, re.IGNORECASE)) for s, n, p in SUSPICIOUS_CMD]
SUSPICIOUS_PATH_RX = re.compile(
    r"%comspec%|cmd(?:\.exe)?\s+/c|powershell|\\temp\\|\\appdata\\|\\users\\public\\|\\programdata\\[^\\]+\.exe|"
    r"https?://|\\\\[\d.]+\\|rundll32|regsvr32|mshta", re.IGNORECASE)
PRIV_GROUPS = re.compile(r"administrators|domain admins|enterprise admins|schema admins|remote desktop users|"
                         r"backup operators|account operators|dnsadmins", re.IGNORECASE)
LOGON_TYPES = {"2": "Interactive", "3": "Network", "4": "Batch", "5": "Service", "7": "Unlock",
               "8": "NetworkCleartext", "9": "NewCredentials", "10": "RemoteInteractive(RDP)",
               "11": "CachedInteractive"}


# ------------------------------------------------------------------ 입력 파싱

def parse_event(elem: ET.Element) -> Dict[str, Any]:
    system = elem.find(f"{NS}System")
    if system is None:
        system = elem.find("System")
    ev: Dict[str, Any] = {"data": {}, "event_id": 0, "time": "", "computer": "", "provider": ""}
    if system is None:
        return ev

    def find(tag: str):
        node = system.find(f"{NS}{tag}")
        return node if node is not None else system.find(tag)

    eid = find("EventID")
    ev["event_id"] = int(eid.text) if eid is not None and eid.text else 0
    tc = find("TimeCreated")
    ev["time"] = tc.get("SystemTime", "") if tc is not None else ""
    comp = find("Computer")
    ev["computer"] = comp.text if comp is not None else ""
    prov = find("Provider")
    ev["provider"] = prov.get("Name", "") if prov is not None else ""

    for data in elem.iter():
        tag = data.tag.split("}")[-1]
        if tag == "Data" and data.get("Name"):
            ev["data"][data.get("Name")] = (data.text or "").strip()
    user_data = elem.find(f"{NS}UserData")
    if user_data is not None:
        for child in user_data.iter():
            if len(child) == 0 and child.text:
                ev["data"].setdefault(child.tag.split("}")[-1], child.text.strip())
    return ev


def iter_xml_events(path: Path) -> Iterator[Dict[str, Any]]:
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    text = re.sub(r"<\?xml[^>]*\?>", "", text).strip()
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        # wevtutil /e 옵션 없이 뽑으면 루트 요소가 없으므로 감싸서 재시도
        root = ET.fromstring(f"<Events>{text}</Events>")
    events = [root] if root.tag.split("}")[-1] == "Event" else [e for e in root if e.tag.split("}")[-1] == "Event"]
    for e in events:
        yield parse_event(e)


def iter_evtx_events(path: Path) -> Iterator[Dict[str, Any]]:
    try:
        import Evtx.Evtx as evtx  # type: ignore
    except ImportError:
        die("EVTX 파싱에는 python-evtx 가 필요합니다: pip install python-evtx\n"
            "    또는 XML로 내보내서 사용: wevtutil qe Security /f:xml /e:Events > security.xml")
    with evtx.Evtx(str(path)) as log:
        for record in log.records():
            try:
                yield parse_event(ET.fromstring(record.xml()))
            except ET.ParseError:
                continue


def iter_events(paths: List[str]) -> Iterator[Dict[str, Any]]:
    for p in paths:
        path = Path(p)
        if path.suffix.lower() == ".evtx":
            yield from iter_evtx_events(path)
        else:
            yield from iter_xml_events(path)


# ------------------------------------------------------------------ 탐지

def finding(ev: Dict[str, Any], severity: str, rule: str, detail: str) -> Dict[str, Any]:
    return {"time": ev["time"], "computer": ev["computer"], "event_id": ev["event_id"],
            "severity": severity, "rule": rule, "detail": detail}


def hunt(events: List[Dict[str, Any]], fail_threshold: int, spray_users: int) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    failures: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"count": 0, "users": set(), "first": "", "last": "", "ev": None})

    for ev in sorted(events, key=lambda e: e["time"]):
        eid, d = ev["event_id"], ev["data"]
        is_sysmon = "sysmon" in ev["provider"].lower()

        if eid == 4625:
            ip = d.get("IpAddress") or "-"
            f = failures[ip]
            f["count"] += 1
            f["users"].add(d.get("TargetUserName", "?"))
            f["first"] = f["first"] or ev["time"]
            f["last"] = ev["time"]
            f["ev"] = f["ev"] or ev

        elif eid == 4624:
            ltype = d.get("LogonType", "")
            ip = d.get("IpAddress") or "-"
            user = d.get("TargetUserName", "?")
            prior = failures.get(ip)
            if ip not in ("-", "127.0.0.1", "::1") and prior and prior["count"] >= 3:
                findings.append(finding(ev, "critical", "logon-after-failures",
                                        f"{user} 로그인 성공 (type {ltype}) ← {ip} 에서 사전 실패 {prior['count']}회"))
            elif ltype == "10":
                findings.append(finding(ev, "medium", "rdp-logon", f"RDP 로그인 {user} from {ip}"))
            elif ltype == "9":
                findings.append(finding(ev, "medium", "new-credentials-logon",
                                        f"LogonType 9 (runas /netonly, Pass-the-Hash 가능성) {user}"))

        elif eid == 4688 or (is_sysmon and eid == 1):
            cmd = d.get("CommandLine", "")
            proc = d.get("NewProcessName") or d.get("Image", "")
            parent = d.get("ParentProcessName") or d.get("ParentImage", "")
            user = d.get("SubjectUserName") or d.get("User", "")
            for sev, name, rx in SUSPICIOUS_CMD_RX:
                if rx.search(cmd):
                    findings.append(finding(ev, sev, f"cmd:{name}",
                                            f"[{user}] {Path(parent.replace(chr(92), '/')).name} → {cmd}"))
            if re.search(r"(?:winword|excel|powerpnt|outlook|acrord32)\.exe$", parent, re.I) and \
               re.search(r"(?:cmd|powershell|wscript|cscript|mshta|rundll32|regsvr32)\.exe$", proc, re.I):
                findings.append(finding(ev, "high", "office-spawns-shell", f"{parent} → {proc}"))

        elif eid == 4720:
            findings.append(finding(ev, "medium", "user-created",
                                    f"계정 생성 {d.get('TargetUserName')} by {d.get('SubjectUserName')}"))

        elif eid in (4728, 4732, 4756):
            group = d.get("TargetUserName", "")
            member = d.get("MemberName") if d.get("MemberName") not in (None, "-") else d.get("MemberSid")
            sev = "high" if PRIV_GROUPS.search(group) else "low"
            findings.append(finding(ev, sev, "group-member-added",
                                    f"{member} → {group} by {d.get('SubjectUserName')}"))

        elif eid in (7045, 4697):
            name = d.get("ServiceName", "")
            image = d.get("ImagePath") or d.get("ServiceFileName", "")
            sev = "high" if SUSPICIOUS_PATH_RX.search(image) else "medium"
            findings.append(finding(ev, sev, "service-installed", f"{name}: {image}"))

        elif eid == 4698:
            content = d.get("TaskContent", "")
            cmd = " ".join(re.findall(r"<(?:Command|Arguments)>(.*?)</", content, re.S))
            sev = "high" if SUSPICIOUS_PATH_RX.search(cmd) else "medium"
            findings.append(finding(ev, sev, "scheduled-task-created",
                                    f"{d.get('TaskName')} by {d.get('SubjectUserName')}: {cmd}"))

        elif eid in (1102, 104):
            findings.append(finding(ev, "high", "log-cleared",
                                    f"이벤트 로그 삭제 by {d.get('SubjectUserName', '?')}"))

    for ip, f in failures.items():
        rules = []
        if f["count"] >= fail_threshold:
            rules.append("bruteforce")
        if len(f["users"]) >= spray_users:
            rules.append("password-spray")
        if rules:
            ev = {**f["ev"], "time": f["first"]}
            findings.append(finding(ev, "high", "+".join(rules),
                                    f"{ip}: 실패 {f['count']}회, 계정 {len(f['users'])}개 "
                                    f"({', '.join(sorted(f['users'])[:8])}) ~ {f['last']}"))

    findings.sort(key=lambda x: (x["time"], SEVERITY[x["severity"]]))
    return findings


def main() -> int:
    setup_stdio()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+", help=".evtx 또는 이벤트 XML 파일")
    ap.add_argument("--fail-threshold", type=int, default=5, help="4625 무차별 대입 판정 횟수 (기본 5)")
    ap.add_argument("--spray-users", type=int, default=4, help="4625 스프레이 판정 계정 수 (기본 4)")
    ap.add_argument("-m", "--min-severity", choices=list(SEVERITY), default="low", help="최소 심각도 (기본 low)")
    ap.add_argument("--stats", action="store_true", help="이벤트 ID별 건수도 출력")
    add_output_args(ap)
    args = ap.parse_args()
    check_files_exist(args.files)

    events = list(iter_events(args.files))
    if not events:
        warn("이벤트를 하나도 읽지 못했습니다")
    findings = [f for f in hunt(events, args.fail_threshold, args.spray_users)
                if SEVERITY[f["severity"]] <= SEVERITY[args.min_severity]]

    if args.stats and args.fmt == "table":
        counts: Dict[int, int] = defaultdict(int)
        for ev in events:
            counts[ev["event_id"]] += 1
        emit([{"event_id": k, "count": v} for k, v in sorted(counts.items())], title="Event ID Stats")
    emit(findings, args.fmt, columns=["time", "computer", "event_id", "severity", "rule", "detail"],
         title=f"Windows Event Findings (총 이벤트 {len(events)})", max_width=140)
    return EXIT_DETECTED if findings else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
