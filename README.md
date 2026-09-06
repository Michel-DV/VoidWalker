# VoidWalker

**VoidWalker** is a zero-dependency Python IoT security auditor for private/local IPv4 networks.

Its primary goal is to help identify **IoT devices that deserve immediate investigation** because they expose risky services, match known vulnerable software fingerprints, or show indicators that may be consistent with compromise.

VoidWalker does this without exploitation, credential attacks, stealth scanning, persistence, or remote command execution.

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![CI](https://github.com/Michel-DV/VoidWalker/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/License-MIT-blue.svg)

## What v2.1 adds

Version **2.1** moves VoidWalker from a focused TCP exposure scanner to an **IoT discovery + fingerprinting + defensive triage** tool while preserving its original purpose.

The pipeline is now:

```text
Private/local IPv4 scope
        |
        +--> bounded concurrent TCP connect scan
        |
        +--> SSDP/UPnP discovery (UDP/1900)
        |
        +--> mDNS/DNS-SD discovery (UDP/5353)
        |
        +--> same-host SSDP device-description metadata
        |
        +--> device/vendor/type correlation
        |
        +--> vulnerability fingerprint matching
        |
        +--> compromise-indicator triage
        |
        +--> terminal or JSON report
```

## Core capabilities

- concurrent TCP connect scanning with a bounded worker pool
- private, loopback, or link-local IPv4 scope only
- 4096-address maximum scope
- IoT-focused and common-service profiles
- custom TCP ports and ranges
- passive service banners and minimal HTTP `HEAD` evidence
- SSDP/UPnP discovery
- mDNS/DNS-SD discovery for common IoT service types
- optional same-host SSDP XML device descriptions
- manufacturer/model/device-type correlation
- machine-readable JSON output
- deterministic findings and device summaries
- vulnerability-candidate detection from explicit software fingerprints
- compromise-indicator detection with confidence levels
- Python 3.11/3.12/3.13 CI
- Ruff lint and formatting checks
- standard-library runtime only

## Why discovery matters

A port scanner can tell you that `192.168.1.50:554` is reachable.

VoidWalker v2.1 tries to add context:

```text
192.168.1.50
  device type: camera
  vendor: Hikvision
  discovery: mDNS
  services:
    RTSP
    HTTP alternate

  HIGH exposure:
    tcp/554 RTSP
    tcp/8000 vendor management

  triage:
    multiple high-risk management surfaces reachable
    confidence: low
```

The additional context helps prioritize which device should be inspected first.

## Vulnerability and compromise triage

VoidWalker deliberately distinguishes between three things.

### Exposure findings

Examples:

- Telnet reachable
- ADB/debug service reachable
- TR-069/CWMP reachable
- RTSP camera stream endpoint reachable
- legacy vendor-management port reachable
- cleartext MQTT reachable

These are **security exposures**, not proof of a vulnerability or infection.

### Vulnerability candidates

When the collected evidence contains a sufficiently specific software fingerprint, VoidWalker can map it to known vulnerability candidates.

Current built-in examples include:

| Fingerprint | Candidate | Confidence |
| --- | --- | --- |
| RomPager `4.34` or earlier | CVE-2014-9222 | High |
| Boa `0.94.14rc21` | CVE-2018-21027, CVE-2018-21028 | High |

A candidate still requires confirmation of the actual device model, firmware, and vendor integration before being treated as a confirmed vulnerability.

### Compromise indicators

VoidWalker also looks for investigation signals such as:

- explicit malware-family strings observed in collected service/discovery evidence
- multiple botnet-targeted management/debug surfaces reachable on the same embedded host

The report always includes a confidence level.

An indicator is **not a malware verdict**. A suspicious device should be followed up with firmware validation, traffic inspection, DNS review, process/file-system analysis where available, and vendor-specific checks.

See [`docs/DETECTION_MODEL.md`](docs/DETECTION_MODEL.md) for the exact reasoning model.

## IoT TCP profile

The default `iot` profile checks services commonly relevant to embedded-device exposure and triage, including:

```text
21      FTP
23      Telnet
81      alternate HTTP
445     SMB
554     RTSP
631     IPP
1883    MQTT
2323    alternate Telnet
4321    uncommon embedded service
5431    vendor/UPnP control
5555    ADB/debug
7547    TR-069/CWMP
8000    vendor/web management
8080    alternate HTTP/admin
8443    alternate HTTPS/admin
8888    alternate HTTP
37215   legacy vendor management
52869   vendor SDK service
```

SSDP `UDP/1900` and mDNS `UDP/5353` are handled by the discovery layer and are intentionally **not** misreported as TCP findings.

## Requirements

- Python 3.11+
- no third-party runtime dependencies

## Usage

Basic local audit:

```bash
python VoidWalker.py
```

Explicit private subnet:

```bash
python VoidWalker.py --network 192.168.1.0/24
```

Use the larger common-service profile:

```bash
python VoidWalker.py --network 192.168.1.0/24 --profile common
```

Custom TCP ports:

```bash
python VoidWalker.py --network 192.168.1.0/24 --ports 22,80,443,554,8000-8010
```

JSON output:

```bash
python VoidWalker.py --network 192.168.1.0/24 --json
```

Pure TCP scanner mode with discovery disabled:

```bash
python VoidWalker.py --network 192.168.1.0/24 --discovery off
```

SSDP only:

```bash
python VoidWalker.py --network 192.168.1.0/24 --discovery ssdp
```

Skip SSDP XML description fetching:

```bash
python VoidWalker.py --network 192.168.1.0/24 --no-descriptions
```

Tune concurrency and timeouts:

```bash
python VoidWalker.py \
  --network 192.168.1.0/24 \
  --workers 96 \
  --timeout 0.5 \
  --banner-timeout 0.2 \
  --discovery-timeout 0.8
```

Version:

```bash
python VoidWalker.py --version
```

## CLI

```text
-n, --network CIDR
--profile {iot,common}
-p, --ports PORTS
-w, --workers N
--timeout SECONDS
--banner-timeout SECONDS
--discovery {off,ssdp,mdns,all}
--discovery-timeout SECONDS
--no-descriptions
--json
--version
```

## SSDP safety boundary

When SSDP returns a `LOCATION` URL, VoidWalker can fetch the UPnP device-description XML to obtain fields such as:

- friendly name
- manufacturer
- model
- model number
- UPnP device type

The description fetch is intentionally constrained:

- HTTP only
- literal host must match the SSDP responder
- no cross-host fetch
- no authentication
- no redirect following
- response capped at 64 KiB

This is metadata collection, not exploitation.

## mDNS discovery

VoidWalker requests common local DNS-SD service types such as:

- HTTP / HTTPS
- RTSP
- MQTT
- SSH
- IPP / printer
- Google Cast
- HomeKit

The parser correlates PTR, SRV, TXT, and IPv4 A records to produce host/service metadata.

## JSON output

JSON reports include:

```text
tool
version
network
hosts_scanned
ports_scanned
findings[]
discovery_records[]
devices[]
indicators[]
duration_ms
interrupted
```

This makes VoidWalker usable as a standalone CLI tool or as a data source for a larger security workflow.

## Design principles

**Find risky IoT devices, not just open ports**  
The scan, discovery, fingerprinting, and triage layers are correlated by host.

**Evidence before verdicts**  
Open ports are exposures. Vulnerability claims require a specific fingerprint. Infection-related output is presented as an indicator with a confidence level.

**Local-network focus**  
Public Internet ranges are intentionally rejected.

**No exploitation**  
VoidWalker does not validate vulnerabilities by triggering them. It produces defensive investigation leads.

**Zero-dependency runtime**  
The scanner and discovery parsers use only the Python standard library.

## Testing

Run the complete suite:

```bash
python -m unittest discover -s tests -v
```

Compile check:

```bash
python -m compileall -q .
```

Optional Ruff development checks:

```bash
python -m pip install ruff
ruff check .
ruff format --check .
```

Tests include localhost-only TCP integration tests and offline parser/signature tests. CI does not scan external systems.

## Limitations

VoidWalker is a triage tool, not a replacement for a full vulnerability scanner, EDR, packet-analysis platform, or firmware-analysis workflow.

Important limitations:

- IPv4 only
- no authenticated device inspection
- no SNMP inventory
- no firmware download or reverse engineering
- no exploit-based vulnerability confirmation
- multicast discovery depends on local network and firewall behavior
- not every IoT device advertises SSDP or mDNS
- malware often does not expose a recognizable banner
- vendor inference is heuristic unless the device advertises explicit metadata

## Legal and ethical use

Use VoidWalker only on networks and devices you own or are explicitly authorized to assess.

## Security model

See [`SECURITY.md`](SECURITY.md).

## Changelog

See [`CHANGELOG.md`](CHANGELOG.md).

## License

MIT. See [`LICENSE`](LICENSE).
