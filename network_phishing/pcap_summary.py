#!/usr/bin/env python3
"""PCAP / PCAPNG 빠른 트리아지 요약 (외부 의존성 없음).

Wireshark를 열기 전에 "이 캡처에 뭐가 있나"를 빠르게 본다.
  - 상위 대화(src → dst:port/proto) 패킷·바이트
  - DNS 질의, HTTP 요청(Host/URI/User-Agent), TLS SNI
  - 비표준 포트 트래픽 (잘 알려진 서비스 포트 외)
지원: Ethernet / Linux SLL / Raw IP 링크, IPv4·IPv6, TCP·UDP (IP 단편 재조립·TCP 스트림 재조립은 하지 않음)

예시:
  pcap_summary.py capture.pcap
  pcap_summary.py capture.pcapng --top 20 --json > summary.json
"""
import argparse
import ipaddress
import struct
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lib.cli import EXIT_OK, check_files_exist, die, setup_stdio, warn  # noqa: E402
from lib.output import emit, emit_sections  # noqa: E402

COMMON_PORTS = {20, 21, 22, 23, 25, 53, 67, 68, 80, 88, 110, 123, 135, 137, 138, 139, 143, 161, 389,
                443, 445, 465, 514, 587, 636, 853, 993, 995, 1433, 1521, 3268, 3306, 3389, 5353, 5355,
                5432, 5985, 5986, 8080, 8443}
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ")


# ------------------------------------------------------------------ 파일 포맷

def read_pcap(data: bytes) -> Iterator[Tuple[float, int, bytes]]:
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError("pcap 형식이 아님")
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    linktype = struct.unpack(f"{endian}I", data[20:24])[0]
    off = 24
    while off + 16 <= len(data):
        sec, frac, incl, _orig = struct.unpack(f"{endian}IIII", data[off:off + 16])
        off += 16
        yield sec + frac / (1e9 if nano else 1e6), linktype, data[off:off + incl]
        off += incl


def read_pcapng(data: bytes) -> Iterator[Tuple[float, int, bytes]]:
    off = 0
    endian = "<"
    interfaces = []  # (linktype, ts_resolution)
    while off + 12 <= len(data):
        btype = struct.unpack(f"{endian}I", data[off:off + 4])[0]
        if btype == 0x0A0D0D0A:  # Section Header Block
            bom = data[off + 8:off + 12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            interfaces = []
        blen = struct.unpack(f"{endian}I", data[off + 4:off + 8])[0]
        if blen < 12:
            break
        body = data[off + 8:off + blen - 4]
        if btype == 0x00000001:  # Interface Description Block
            linktype = struct.unpack(f"{endian}H", body[:2])[0]
            res = 1e6
            opt = 8
            while opt + 4 <= len(body):
                code, olen = struct.unpack(f"{endian}HH", body[opt:opt + 4])
                if code == 0:
                    break
                if code == 9 and olen >= 1:  # if_tsresol
                    v = body[opt + 4]
                    res = 2 ** (v & 0x7F) if v & 0x80 else 10 ** v
                opt += 4 + ((olen + 3) & ~3)
            interfaces.append((linktype, res))
        elif btype == 0x00000006 and interfaces:  # Enhanced Packet Block
            iface, ts_hi, ts_lo, cap = struct.unpack(f"{endian}IIII", body[:16])
            linktype, res = interfaces[iface] if iface < len(interfaces) else interfaces[0]
            yield ((ts_hi << 32) | ts_lo) / res, linktype, body[20:20 + cap]
        elif btype == 0x00000003 and interfaces:  # Simple Packet Block
            yield 0.0, interfaces[0][0], body[4:]
        off += blen


def read_packets(path: Path) -> Iterator[Tuple[float, int, bytes]]:
    data = path.read_bytes()
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        return read_pcapng(data)
    return read_pcap(data)


# ------------------------------------------------------------------ 프로토콜 파싱

def l3_offset(linktype: int, frame: bytes) -> Optional[Tuple[int, int]]:
    """(ethertype, ip 헤더 시작 오프셋)"""
    if linktype == 1:  # Ethernet
        if len(frame) < 14:
            return None
        etype, off = struct.unpack("!H", frame[12:14])[0], 14
        while etype in (0x8100, 0x88A8) and len(frame) >= off + 4:  # VLAN
            etype, off = struct.unpack("!H", frame[off + 2:off + 4])[0], off + 4
        return etype, off
    if linktype == 113:  # Linux cooked (SLL)
        return struct.unpack("!H", frame[14:16])[0], 16
    if linktype in (101, 228, 229, 12, 14):  # Raw IP
        return (0x0800 if frame[:1] and frame[0] >> 4 == 4 else 0x86DD), 0
    if linktype == 0:  # BSD loopback
        family = struct.unpack("<I", frame[:4])[0]
        return (0x0800 if family == 2 else 0x86DD), 4
    return None


def parse_ip(etype: int, pkt: bytes) -> Optional[Tuple[str, str, int, bytes]]:
    if etype == 0x0800 and len(pkt) >= 20:
        ihl = (pkt[0] & 0x0F) * 4
        total = struct.unpack("!H", pkt[2:4])[0] or len(pkt)
        frag = struct.unpack("!H", pkt[6:8])[0] & 0x1FFF
        if frag:
            return None
        return (str(ipaddress.IPv4Address(pkt[12:16])), str(ipaddress.IPv4Address(pkt[16:20])),
                pkt[9], pkt[ihl:total])
    if etype == 0x86DD and len(pkt) >= 40:
        return (str(ipaddress.IPv6Address(pkt[8:24])), str(ipaddress.IPv6Address(pkt[24:40])),
                pkt[6], pkt[40:])
    return None


def dns_qname(payload: bytes) -> Optional[Tuple[str, bool]]:
    """DNS 메시지에서 (첫 질의 이름, 응답 여부)."""
    if len(payload) < 12:
        return None
    flags, qd = struct.unpack("!HH", payload[2:6])
    if qd == 0:
        return None
    labels, off = [], 12
    while off < len(payload):
        n = payload[off]
        if n == 0:
            break
        if n & 0xC0 or off + 1 + n > len(payload):
            return None
        labels.append(payload[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    return (".".join(labels).lower(), bool(flags & 0x8000)) if labels else None


def tls_sni(payload: bytes) -> Optional[str]:
    """TLS ClientHello 의 server_name 확장."""
    try:
        if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        off = 9 + 2 + 32  # record(5) + hs type/len(4) + version(2) + random(32)
        off += 1 + payload[off]  # session id
        off += 2 + struct.unpack("!H", payload[off:off + 2])[0]  # cipher suites
        off += 1 + payload[off]  # compression
        end = off + 2 + struct.unpack("!H", payload[off:off + 2])[0]
        off += 2
        while off + 4 <= min(end, len(payload)):
            etype, elen = struct.unpack("!HH", payload[off:off + 4])
            if etype == 0:
                name_len = struct.unpack("!H", payload[off + 7:off + 9])[0]
                return payload[off + 9:off + 9 + name_len].decode("ascii", "replace").lower()
            off += 4 + elen
    except (IndexError, struct.error):
        pass
    return None


def http_request(payload: bytes) -> Optional[Dict[str, str]]:
    if not payload.startswith(HTTP_METHODS):
        return None
    head = payload.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace").split("\r\n")
    parts = head[0].split(" ")
    headers = {}
    for line in head[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return {"method": parts[0], "uri": parts[1] if len(parts) > 1 else "",
            "host": headers.get("host", ""), "user_agent": headers.get("user-agent", "")}


# ------------------------------------------------------------------ 요약

def summarize(path: Path, top: int) -> Dict[str, Any]:
    total = 0
    total_bytes = 0
    first_ts = last_ts = None
    skipped = 0
    protos: Counter = Counter()
    talkers: Counter = Counter()
    convs: Dict[Tuple[str, str, int, str], list] = defaultdict(lambda: [0, 0])
    dns: Dict[Tuple[str, str], int] = Counter()
    http: Counter = Counter()
    sni: Counter = Counter()

    for ts, linktype, frame in read_packets(path):
        total += 1
        total_bytes += len(frame)
        if ts:
            first_ts = ts if first_ts is None else min(first_ts, ts)
            last_ts = ts if last_ts is None else max(last_ts, ts)
        l3 = l3_offset(linktype, frame)
        ip = parse_ip(l3[0], frame[l3[1]:]) if l3 else None
        if not ip:
            skipped += 1
            continue
        src, dst, proto, l4 = ip
        talkers[src] += len(frame)

        if proto == 6 and len(l4) >= 20:
            sport, dport = struct.unpack("!HH", l4[:4])
            payload = l4[(l4[12] >> 4) * 4:]
            pname = "tcp"
        elif proto == 17 and len(l4) >= 8:
            sport, dport = struct.unpack("!HH", l4[:4])
            payload = l4[8:]
            pname = "udp"
        else:
            pname = {1: "icmp", 58: "icmpv6", 47: "gre", 50: "esp"}.get(proto, f"ip-{proto}")
            protos[pname] += 1
            c = convs[(src, dst, 0, pname)]
            c[0] += 1
            c[1] += len(frame)
            continue
        protos[pname] += 1

        # 서버 포트 추정: 잘 알려진 포트 또는 더 작은 포트
        if sport in COMMON_PORTS and dport not in COMMON_PORTS:
            key = (dst, src, sport, pname)
        elif dport in COMMON_PORTS or dport <= sport:
            key = (src, dst, dport, pname)
        else:
            key = (dst, src, sport, pname)
        c = convs[key]
        c[0] += 1
        c[1] += len(frame)

        if 53 in (sport, dport) or 5353 in (sport, dport):
            q = dns_qname(payload[2:] if pname == "tcp" else payload)
            if q and not q[1]:
                dns[(src, q[0])] += 1
        elif pname == "tcp" and payload:
            req = http_request(payload)
            if req:
                http[(src, req["host"] or dst, req["method"], req["uri"][:120], req["user_agent"][:80])] += 1
            else:
                name = tls_sni(payload)
                if name:
                    sni[(src, dst, dport, name)] += 1

    def fmt_ts(t: Optional[float]) -> str:
        return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if t else "-"

    conv_rows = [{"client": k[0], "server": k[1], "port": k[2], "proto": k[3], "packets": v[0], "bytes": v[1]}
                 for k, v in convs.items()]
    conv_rows.sort(key=lambda r: -r["bytes"])
    return {
        "Overview": [{
            "file": path.name, "packets": total, "bytes": total_bytes, "start": fmt_ts(first_ts),
            "end": fmt_ts(last_ts), "duration_s": round((last_ts or 0) - (first_ts or 0), 1),
            "non_ip_or_skipped": skipped, "protocols": [f"{k}:{v}" for k, v in protos.most_common()],
        }],
        "Top Talkers (bytes sent)": [{"ip": ip, "bytes": b} for ip, b in talkers.most_common(top)],
        "Top Conversations": conv_rows[:top],
        "Non-standard Ports": [r for r in conv_rows if r["proto"] in ("tcp", "udp")
                               and r["port"] not in COMMON_PORTS and r["port"] < 49152][:top],
        "DNS Queries": [{"client": k[0], "query": k[1], "count": v}
                        for k, v in sorted(dns.items(), key=lambda kv: -kv[1])][: top * 3],
        "HTTP Requests": [{"client": k[0], "host": k[1], "method": k[2], "uri": k[3], "user_agent": k[4], "count": v}
                          for k, v in http.most_common(top * 3)],
        "TLS SNI": [{"client": k[0], "server": k[1], "port": k[2], "sni": k[3], "count": v}
                    for k, v in sni.most_common(top * 3)],
    }


def main() -> int:
    setup_stdio()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", help=".pcap 또는 .pcapng 파일")
    ap.add_argument("-n", "--top", type=int, default=10, help="각 섹션 상위 N개 (기본 10)")
    ap.add_argument("--json", action="store_true", help="JSON으로 출력")
    args = ap.parse_args()
    check_files_exist([args.file])

    try:
        result = summarize(Path(args.file), args.top)
    except ValueError as e:
        die(f"{args.file}: {e}")
    if result["Overview"][0]["non_ip_or_skipped"]:
        warn(f"IP가 아니거나 해석하지 못한 패킷 {result['Overview'][0]['non_ip_or_skipped']}개")
    if args.json:
        emit_sections(result, "json")
    else:
        emit(result["Overview"], title="Overview", max_width=120)
        emit_sections({k: v for k, v in result.items() if k != "Overview"})
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
