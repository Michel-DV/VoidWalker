# VoidWalker

A fast, dependency-free **local IoT TCP exposure auditor** written in Python.

VoidWalker v2.0 is designed for home labs, classrooms, device inventories, and authorized internal security assessments. It identifies reachable management, debug, legacy-cleartext, and IoT-related TCP services on private networks, then reports them as **exposure signals** for manual review.

It does **not** claim that an open port proves malware infection or a vulnerability.

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![CI](https://github.com/Michel-DV/VoidWalker/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/License-MIT-blue.svg)

## Why v2.0

The original VoidWalker concept worked, but mixed useful network auditing with overly strong conclusions. For example, a reachable Telnet or ADB port can be risky without proving Mirai/Kimwolf infection, and SSDP normally uses **UDP/1900**, while the original scanner tested it with TCP.

Version 2.0 keeps the useful idea and rebuilds the scanner around accurate reporting, predictable concurrency, machine-readable output, tests, and explicit safety boundaries.

## Features

- concurrent TCP connect scanning with a bounded worker pool
- built-in `iot` and `common` port profiles
- custom port lists and ranges
- passive banner collection for server-speaks-first protocols
- minimal HTTP `HEAD` evidence collection for web-management ports
- deterministic results sorted by host, severity, and port
- JSON output for scripts and pipelines
- private/local IPv4 scope validation
- maximum scope of 4096 addresses to prevent accidental broad scans
- automatic local `/24` suggestion when no network is supplied
- zero third-party runtime dependencies
- unit and localhost-only integration tests
- CI on Python 3.11, 3.12, and 3.13

## Quick start

```bash
git clone https://github.com/Michel-DV/VoidWalker.git
cd VoidWalker
python VoidWalker.py --network 192.168.1.0/24
```

If `--network` is omitted, VoidWalker derives a local `/24` from the preferred IPv4 address. If only loopback is available, it falls back to `127.0.0.1/32`.

## Usage

```text
python VoidWalker.py [options]
```

Examples:

```bash
# Default IoT exposure profile
python VoidWalker.py --network 192.168.1.0/24

# Broader common-services profile
python VoidWalker.py --network 10.10.20.0/24 --profile common

# Custom TCP ports
python VoidWalker.py --network 192.168.50.0/24 --ports 22,80,443,1883,8000-8010

# Faster local lab scan with shorter timeout
python VoidWalker.py --network 192.168.56.0/24 --workers 200 --timeout 0.3

# JSON output
python VoidWalker.py --network 192.168.1.0/24 --json

# Disable evidence reads while keeping connect checks
python VoidWalker.py --network 192.168.1.0/24 --banner-timeout 0
```

## Built-in profiles

### `iot` (default)

Focuses on TCP services that frequently deserve review on embedded devices:

| Port | Service | Signal |
| ---: | --- | --- |
| 21 | FTP | legacy cleartext |
| 23 | Telnet | legacy cleartext |
| 2323 | alternate Telnet | legacy cleartext |
| 445 | SMB | file sharing |
| 5555 | ADB / debug service | debug interface |
| 5431 | UPnP control / vendor service | management |
| 7547 | TR-069 / CWMP | management |
| 8080 | alternate HTTP / admin UI | web management |
| 8888 | alternate HTTP | web management |
| 37215 | vendor management service | legacy vendor service |
| 52869 | vendor SDK service | legacy vendor service |

### `common`

Adds SSH, HTTP, HTTPS, MQTT, and MQTT over TLS to the IoT profile for broader device inventory work.

## Important correction: SSDP

SSDP/UPnP discovery normally uses **UDP port 1900**. VoidWalker v2.0 is intentionally a TCP scanner, so UDP/1900 is not represented as if it were a TCP finding.

A later version can add a separate, clearly identified UDP discovery module without conflating transport protocols.

## Example output

```text
VoidWalker v2.0.0 - local IoT exposure auditor
Scope: 192.168.1.0/24
Hosts: 254 | TCP ports: 11 | Findings: 3
----------------------------------------------------------------------------
[HIGH  ] 192.168.1.40:23    Telnet  (legacy-cleartext)
         Telnet exposes an unauthenticated or weakly protected management surface on many IoT devices.
         evidence: BusyBox telnetd
[MEDIUM] 192.168.1.55:8080  HTTP alternate / admin UI  (web-management)
         Alternate HTTP ports often host device administration panels.
         evidence: HTTP/1.0 200 OK Server: embedded-web
----------------------------------------------------------------------------
Finished in 1.14s
Open ports are exposure signals, not proof of vulnerability or compromise.
```

## JSON schema

```json
{
  "tool": "VoidWalker",
  "version": "2.0.0",
  "network": "192.168.1.0/24",
  "hosts_scanned": 254,
  "ports_scanned": [21, 23, 445, 2323, 5431, 5555, 7547, 8080, 8888, 37215, 52869],
  "findings": [
    {
      "host": "192.168.1.40",
      "port": 23,
      "service": "Telnet",
      "category": "legacy-cleartext",
      "severity": "high",
      "note": "...",
      "evidence": "BusyBox telnetd"
    }
  ],
  "duration_ms": 1140,
  "interrupted": false
}
```

## Safety boundaries

VoidWalker v2.0 intentionally accepts only private, loopback, or link-local IPv4 networks and refuses scopes larger than 4096 addresses. It performs normal TCP connection attempts only.

There is no raw SYN scanning, evasion, credential attack, exploitation, persistence, malware functionality, or remote command execution.

See [`SECURITY.md`](SECURITY.md) for the full boundary.

## Testing

```bash
python -m unittest discover -s tests -v
python -m compileall -q .
```

Optional development checks:

```bash
python -m pip install ruff==0.16.6
ruff check .
ruff format --check .
```

The network tests use listeners on `127.0.0.1` only.

## Limitations

- IPv4 only in v2.0
- TCP only
- no UDP discovery yet
- no OS fingerprinting
- no vulnerability exploitation
- no malware detection engine
- service names are based on the selected port profile, not deep fingerprinting
- passive/HTTP evidence is best-effort and may be absent even when a port is reachable

For deep authorized assessments, pair VoidWalker with mature tools such as Nmap and vendor-specific vulnerability management workflows.

## Legal use

Use VoidWalker only on networks and systems you own or are explicitly authorized to assess.

## License

MIT. See [LICENSE](LICENSE).
