#!/usr/bin/env python3
"""dns.log / sample.pcap 합성 샘플 생성기 (결정적: 항상 같은 결과).

    python samples/generate_samples.py
"""
import random
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = datetime(2026, 9, 26, 8, 0, 0, tzinfo=timezone.utc)


def gen_dns_log(path: Path) -> None:
    rnd = random.Random(42)
    events = []
    # 1) 비커닝: 60초 ±2초 간격
    t = BASE
    for _ in range(30):
        events.append((t, "10.0.0.23", "cdn-telemetry.top", "A"))
        t += timedelta(seconds=60 + rnd.uniform(-2, 2))
    # 2) 정상 사용자: 불규칙 간격
    t = BASE
    for _ in range(30):
        events.append((t, "10.0.0.5", rnd.choice(["www.google.com", "github.com", "outlook.office365.com"]), "A"))
        t += timedelta(seconds=rnd.expovariate(1 / 90))
    # 3) DGA 의심
    t = BASE + timedelta(minutes=5)
    for _ in range(20):
        label = "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(rnd.randint(14, 20)))
        events.append((t, "10.0.0.31", f"{label}.{rnd.choice(['com', 'net', 'info'])}", "A"))
        t += timedelta(seconds=rnd.uniform(0.5, 3))
    # 4) DNS 터널링 의심: 긴 hex 서브도메인
    t = BASE + timedelta(minutes=10)
    for i in range(40):
        chunk = "".join(rnd.choice("0123456789abcdef") for _ in range(50))
        events.append((t, "10.0.0.44", f"{chunk}.{i}.t.exfil-dns.xyz", "TXT"))
        t += timedelta(seconds=rnd.uniform(0.2, 1))

    events.sort()
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write("# timestamp client query qtype\n")
        for ts, client, q, qtype in events:
            fh.write(f"{ts.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]}Z {client} {q} {qtype}\n")


# ------------------------------------------------------------------ PCAP

def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _ip(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0x4000, 64, proto, 0,
                      bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))
    hdr = hdr[:10] + struct.pack("!H", _checksum(hdr)) + hdr[12:]
    return hdr + payload


def _eth(ip_packet: bytes) -> bytes:
    return b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00" + ip_packet


def _udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _tcp(sport: int, dport: int, payload: bytes, flags: int = 0x18) -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, 1000, 0, 5 << 4, flags, 65535, 0, 0) + payload


def _dns_query(qname: str, txid: int) -> bytes:
    q = b"".join(bytes([len(p)]) + p.encode() for p in qname.split(".")) + b"\0"
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 1, 1)


def _tls_client_hello(sni: str) -> bytes:
    name = sni.encode()
    sni_ext = struct.pack("!HHHBH", 0x0000, len(name) + 5, len(name) + 3, 0, len(name)) + name
    body = (b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
            + struct.pack("!H", len(sni_ext)) + sni_ext)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def gen_pcap(path: Path) -> None:
    packets = []
    t = BASE.timestamp()

    def add(frame: bytes) -> None:
        nonlocal t
        packets.append((t, frame))
        t += 0.25

    for i, q in enumerate(["www.example.com", "cdn-telemetry.top", "update-check.xyz", "github.com"]):
        add(_eth(_ip("10.0.0.23", "10.0.0.1", 17, _udp(53000 + i, 53, _dns_query(q, 0x1000 + i)))))
    http = (b"GET /payload.bin HTTP/1.1\r\nHost: update-check.xyz\r\n"
            b"User-Agent: Mozilla/4.0 (compatible; MSIE 6.0)\r\n\r\n")
    add(_eth(_ip("10.0.0.23", "45.133.1.20", 6, _tcp(49200, 80, http))))
    add(_eth(_ip("10.0.0.23", "185.220.101.45", 6, _tcp(49201, 443, _tls_client_hello("cdn-telemetry.top")))))
    add(_eth(_ip("10.0.0.23", "140.82.112.3", 6, _tcp(49202, 443, _tls_client_hello("github.com")))))
    for _ in range(12):  # 비표준 포트 (리버스 셸 흉내)
        add(_eth(_ip("10.0.0.23", "203.0.113.66", 6, _tcp(49300, 4444, b"whoami\n"))))
        add(_eth(_ip("203.0.113.66", "10.0.0.23", 6, _tcp(4444, 49300, b"nt authority\\system\n"))))

    with path.open("wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in packets:
            sec = int(ts)
            fh.write(struct.pack("<IIII", sec, int((ts - sec) * 1e6), len(frame), len(frame)))
            fh.write(frame)


if __name__ == "__main__":
    import sys
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    gen_dns_log(HERE / "dns.log")
    gen_pcap(HERE / "sample.pcap")
    print("생성 완료: samples/dns.log, samples/sample.pcap")
