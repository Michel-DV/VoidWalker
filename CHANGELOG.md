# Changelog

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
