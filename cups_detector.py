#!/usr/bin/env python3
"""cups_detector.py - detect suspicious CUPS printer-discovery activity with Scapy.

Reads a pcap (offline) or sniffs an interface (live) and raises alerts for:
  UNAUTHORIZED_ADVERT  browse packet from a sender / pointing to a printer not on the allowlist
  REDIRECTED_ADVERT    advertised printer address differs from the sender (spoofing / redirection)
  MALFORMED_ADVERT     browse packet that breaks the protocol format or has odd field values
  ADVERT_FLOOD         too many browse packets from one sender in a short time
  SUSPICIOUS_IPP       a host opens a connection / sends IPP to an advertised, non-allowlisted printer

Examples:
  python3 cups_detector.py -r pcap_files/03_attack_basic.pcap --allow 172.20.0.20 -o evidence/alerts.json
  sudo python3 cups_detector.py -i br-cups --allow 172.20.0.20 -o evidence/live.csv
"""
import argparse
import csv
import json
import re
from collections import defaultdict, deque
from datetime import datetime
from urllib.parse import urlsplit

from scapy.all import IP, TCP, UDP, Raw, PcapReader, sniff

# <type> <state> <uri> "<location>" "<info>" [optional extra fields]
BROWSE_RE = re.compile(r'^([0-9a-fA-F]+) ([0-9a-fA-F]+) (\S+) "([^"]*)" "([^"]*)"')
GOOD_SCHEMES = {"ipp", "ipps", "http", "https"}
MAX_LEN = 1024


class Detector:
    def __init__(self, allow, flood_count, flood_window):
        self.allow = set(allow)
        self.flood_count, self.flood_window = flood_count, flood_window
        self.alerts = []
        self.seen = defaultdict(deque)   # sender -> timestamps of recent browse packets
        self.flooding = set()            # senders already alerted for the current flood
        self.advertised = set()          # (host, port) announced by non-allowlisted adverts
        self.reported_flows = set()

    def alert(self, pkt, severity, rule, detail):
        a = {"time": datetime.fromtimestamp(float(pkt.time)).isoformat(timespec="milliseconds"),
             "severity": severity, "rule": rule, "src": pkt[IP].src, "dst": pkt[IP].dst,
             "detail": detail}
        self.alerts.append(a)
        print(f"[{a['severity']:6}] {a['time']} {a['rule']:20} {a['src']} -> {a['dst']}  {a['detail']}")

    def handle(self, pkt):
        if not pkt.haslayer(IP):
            return
        if pkt.haslayer(UDP) and pkt[UDP].dport == 631:
            self.browse(pkt)
        elif pkt.haslayer(TCP):
            self.tcp(pkt)

    def browse(self, pkt):
        src, t = pkt[IP].src, float(pkt.time)
        data = bytes(pkt[UDP].payload)

        # Rule: repeated / abnormal number of discovery messages
        q = self.seen[src]
        q.append(t)
        while q and t - q[0] > self.flood_window:
            q.popleft()
        if len(q) >= self.flood_count and src not in self.flooding:
            self.flooding.add(src)
            self.alert(pkt, "MEDIUM", "ADVERT_FLOOD",
                       f"{len(q)} browse packets in {self.flood_window}s from {src}")
        elif len(q) < self.flood_count:
            self.flooding.discard(src)

        # Rule: malformed / unexpected fields
        problems = []
        if len(data) > MAX_LEN:
            problems.append(f"length {len(data)} > {MAX_LEN}")
        text = data.decode("utf-8", errors="replace").rstrip("\n")
        if any(ord(c) < 32 or c == "�" for c in text):
            problems.append("non-printable bytes")
        m = BROWSE_RE.match(text)
        if not m:
            self.alert(pkt, "HIGH", "MALFORMED_ADVERT", f"does not match browse format: {text[:80]!r}")
            return
        ptype, state, uri = m.group(1), m.group(2), m.group(3)
        u = urlsplit(uri)
        if u.scheme not in GOOD_SCHEMES:
            problems.append(f"scheme '{u.scheme}'")
        if not re.match(r"^/(printers|classes)/[^/]+$", u.path):
            problems.append(f"path '{u.path}'")
        if int(state, 16) not in (3, 4, 5):
            problems.append(f"printer-state {state}")
        if int(ptype, 16) > 0xFFFFFFFF:
            problems.append(f"printer-type {ptype}")
        try:
            port = u.port or 631
        except ValueError:
            port = None
            problems.append(f"bad port in '{u.netloc}'")
        if port and port != 631:
            problems.append(f"non-standard port {port}")
        if problems:
            self.alert(pkt, "MEDIUM", "MALFORMED_ADVERT", "; ".join(problems) + f" | {uri}")

        # Rule: unauthorized printer advertisement
        host = u.hostname or ""
        if src not in self.allow or host not in self.allow:
            self.alert(pkt, "HIGH", "UNAUTHORIZED_ADVERT", f"sender {src} advertises {uri}")
            if port:
                self.advertised.add((host, port))
        if host and host != src:
            self.alert(pkt, "MEDIUM", "REDIRECTED_ADVERT", f"sender {src} points victims to {host}")

    def tcp(self, pkt):
        dst, dport = pkt[IP].dst, pkt[TCP].dport
        if dst in self.allow:
            return
        flow = (pkt[IP].src, pkt[TCP].sport, dst, dport)
        if flow in self.reported_flows:
            return
        # Rule: suspicious IPP connection - to an advertised rogue printer, or IPP to a non-allowed host
        if pkt[TCP].flags == "S" and (dst, dport) in self.advertised:
            reason = "connection to advertised rogue printer"
        elif pkt.haslayer(Raw) and is_ipp_request(bytes(pkt[Raw].load)):
            reason = "IPP request to non-allowlisted host"
        else:
            return
        self.reported_flows.add(flow)
        self.alert(pkt, "HIGH", "SUSPICIOUS_IPP", f"{reason} {dst}:{dport}")


def is_ipp_request(load):
    """HTTP POST carrying IPP. Responses also say application/ipp, so they must not count."""
    return load.startswith(b"POST ") and b"application/ipp" in load[:1024].lower()


def save(alerts, path):
    with open(path, "w", newline="") as f:
        if path.endswith(".csv"):
            w = csv.DictWriter(f, fieldnames=["time", "severity", "rule", "src", "dst", "detail"])
            w.writeheader()
            w.writerows(alerts)
        else:
            json.dump(alerts, f, indent=2)


def main():
    p = argparse.ArgumentParser(description="Detect suspicious CUPS printer-discovery traffic.")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("-r", "--read", nargs="+", help="pcap file(s) to analyse offline")
    src.add_argument("-i", "--iface", help="interface to monitor live")
    p.add_argument("-t", "--timeout", type=int, help="stop live monitoring after N seconds")
    p.add_argument("-a", "--allow", nargs="*", default=[], help="authorized printer / print-server IPs")
    p.add_argument("--flood-count", type=int, default=5, help="browse packets that count as a flood")
    p.add_argument("--flood-window", type=float, default=10, help="flood time window in seconds")
    p.add_argument("-o", "--out", help="write alerts to .json or .csv")
    a = p.parse_args()

    d = Detector(a.allow, a.flood_count, a.flood_window)
    if a.read:
        for path in a.read:
            print(f"== {path}")
            with PcapReader(path) as pcap:
                for pkt in pcap:
                    d.handle(pkt)
    else:
        print(f"== live on {a.iface} (Ctrl+C to stop)")
        sniff(iface=a.iface, filter="udp port 631 or tcp", prn=d.handle, store=False, timeout=a.timeout)

    counts = defaultdict(int)
    for x in d.alerts:
        counts[x["rule"]] += 1
    print(f"== {len(d.alerts)} alert(s): " + (", ".join(f"{k}={v}" for k, v in counts.items()) or "none"))
    if a.out:
        save(d.alerts, a.out)
        print(f"== saved to {a.out}")


if __name__ == "__main__":
    main()
