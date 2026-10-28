# CUPS Printer Discovery Exploitation and Detection (Scapy)

DAT505 Ethical Hacking - Assignment 2.

Two Scapy tools for investigating the insecure CUPS printer-discovery mechanism
(CVE-2024-47176 and related `cups-browsed` issues):

- `cups_attack.py` - advertises an attacker-controlled printer to a vulnerable
  `cups-browsed` and shows that the victim connects back to it.
- `cups_detector.py` - detects suspicious CUPS discovery traffic, live or from a
  pcap file, and exports alerts to JSON or CSV.

> **For isolated lab use only.** Everything here runs against a local Docker
> container on a private network. Never point these tools at public, university
> or third-party systems without authorization.

## Requirements

- Linux with Python 3 and root (raw sockets need it)
- `pip install -r requirements.txt` (Scapy)
- Docker + Docker Compose for the lab

## Lab setup

```bash
cd lab
docker compose up -d       # victim (vulnerable cups-browsed) + a legit print server
```

| Role | Container | IP |
|------|-----------|----|
| Attacker | the host itself | 172.20.0.1 |
| Victim | `cups-victim` (`vulhub/cups-browsed:2.0.1`) | 172.20.0.10 |
| Legit printer | `legit-printer` (CUPS sharing `Office-Printer`) | 172.20.0.20 |

The bridge is named `br-cups`, so capture with `tcpdump -i br-cups`.

## Attack tool

Send one spoofed printer advertisement and watch for the callback:

```bash
sudo python3 cups_attack.py -t 172.20.0.10 -p 172.20.0.1 \
    --pcap pcap_files/attack.pcap --log attack.log
```

Useful options:

| Option | Meaning |
|--------|---------|
| `-t` | victim IP |
| `-p` / `-P` | advertised printer IP / port |
| `--scheme` | `ipp`, `ipps`, `http` ... |
| `-n --info --location` | advertisement fields |
| `--src` | spoof the UDP source IP |
| `-c -i` | send many packets (count / interval) |
| `--raw` | send any payload (malformed tests) |
| `--pcap --log` | save capture / log |

A small fake IPP printer runs automatically so the callback can be observed;
it only returns harmless attributes (no PPD injection, no RCE).

## Detection tool

Offline:

```bash
python3 cups_detector.py -r pcap_files/attack.pcap -a 172.20.0.20 -o alerts.json
```

Live:

```bash
sudo python3 cups_detector.py -i br-cups -a 172.20.0.20 -o alerts.csv
```

`-a` lists the authorized printer IPs (allowlist). Rules:
`UNAUTHORIZED_ADVERT`, `REDIRECTED_ADVERT`, `SUSPICIOUS_IPP`, `ADVERT_FLOOD`,
`MALFORMED_ADVERT`. Output is `.json` or `.csv` by extension.

## Repository layout

- `cups_attack.py`, `cups_detector.py` - the tools
- `lab/docker-compose.yml` - the isolated lab
- `pcap_files/` - captured traffic (normal, attack, variations, mitigations)
- `evidence/` - logs and detector output
- `requirements.txt`

The full write-up (environment, experiments, results, mitigations, ethics) is in
the PDF report submitted separately.
