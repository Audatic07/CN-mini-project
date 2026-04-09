# Custom DNS Server

Run guide (`udp_server.py` on port `53`).

## What Is In The Code

- `udp_server.py`: main UDP DNS server, request handling pipeline, and logging.
- `forwarder.py`: upstream DNS forwarding with round-robin selection and timeout handling.
- `cache.py`: in-memory DNS cache with TTL-based expiry helpers.
- `blocklist.py`: loads and normalizes blocked domains from file.
- `blocklist.txt`: one blocked domain per line.
- `local_hosts.json`: static local overrides in `{"domain": "ip"}` format.

## Request Flow

1. Parse incoming DNS packet.
2. If domain is blocked, return `0.0.0.0`.
3. Else check cache and return cached response if valid.
4. Else check local hosts mapping and return static IP if found.
5. Else forward to upstream DNS servers.
6. Cache reply using TTL and write a log entry.

## Install

```powershell
pip install dnslib
```

## Run

Open PowerShell as Administrator, then:

```powershell
cd C:/OpenSource/CN-mini-project
python udp_server.py
```

## Query

Run from another terminal:

```powershell
nslookup facebook.com 127.0.0.1
nslookup intranet.local 127.0.0.1
nslookup example.com 127.0.0.1
```

Expected:

- `facebook.com` -> `0.0.0.0`
- `intranet.local` -> `192.168.1.10`
- `example.com` -> public IPs
