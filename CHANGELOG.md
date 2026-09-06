# Changelog

## 2.1.0

### Added

- SSDP/UPnP discovery over UDP/1900
- mDNS/DNS-SD discovery over UDP/5353
- bounded same-host UPnP XML device-description retrieval
- device name, manufacturer, model, type, source, and service correlation
- lightweight vendor/device-type inference
- vulnerability-candidate engine with confidence levels
- RomPager affected-range detection for CVE-2014-9222
- Boa 0.94.14rc21 detection for CVE-2018-21027 and CVE-2018-21028
- explicit IoT malware-family string triage
- low-confidence multi-surface compromise-suspicion heuristic
- `--discovery`, `--discovery-timeout`, and `--no-descriptions`
- JSON `discovery_records`, `devices`, and `indicators` sections
- detection-model documentation
- offline SSDP, mDNS, fingerprint, vulnerability, and compromise-indicator tests

### Changed

- expanded the IoT TCP profile with RTSP, IPP, alternate web-management, and uncommon embedded services
- reframed the primary report around device intelligence, exposures, and vulnerability/compromise triage
- increased collected banner evidence length from 160 to 240 characters
- preserved UDP/1900 and UDP/5353 as discovery protocols instead of misclassifying them as TCP findings

### Security

- public Internet scopes remain rejected
- SSDP description retrieval is same-host, HTTP-only, bounded, and does not follow redirects
- vulnerability matches are fingerprint-based and do not trigger or exploit the candidate issue
- compromise output remains confidence-scored and explicitly non-conclusive

## 2.0.0

### Added

- argparse CLI with profiles, custom ports, timeouts, worker tuning, JSON output, and version flag
- private/local IPv4 scope validation and a 4096-address safety cap
- bounded concurrent endpoint scanning instead of sequential per-host port loops
- structured findings and deterministic sorting
- lightweight passive/HTTP evidence collection
- unit and localhost integration tests
- GitHub Actions CI across Python 3.11, 3.12, and 3.13
- Ruff lint/format configuration
- security policy and explicit scanner boundaries

### Changed

- reframed results as exposure signals instead of botnet/vulnerability verdicts
- corrected the previous TCP/SSDP mismatch by removing UDP/1900 from the TCP profile
- replaced bare exception handlers with explicit network/protocol errors
- eliminated the ineffective per-call threading lock
- avoided materializing the entire host list before scanning

### Removed

- public Internet scanning from the default operating model
- claims that an open port alone proves Mirai, Gafgyt, Kimwolf, or another compromise
