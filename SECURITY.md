# Security policy

VoidWalker is intentionally scoped as a defensive IoT discovery and exposure-triage tool for private/local IPv4 networks.

## Security boundaries

- IPv4 only
- private, loopback, or link-local targets only
- maximum scope: 4096 addresses
- standard TCP connect scanning only
- SSDP/UPnP and mDNS/DNS-SD local discovery
- same-host HTTP-only UPnP description retrieval
- no raw SYN or stealth scanning
- no credential attacks
- no brute force
- no exploitation
- no persistence
- no remote code execution
- no destructive validation
- no vulnerability claim based only on an open port
- no infection verdict based only on a suspicious service combination

## Triage semantics

VoidWalker reports three different classes of information:

1. directly observed service exposures
2. vulnerability candidates backed by a specific collected fingerprint
3. compromise indicators or suspicions with an explicit confidence level

A vulnerability candidate still requires device/firmware confirmation.

A compromise indicator is an investigation lead, not standalone proof of malware.

## SSDP description safety

UPnP description retrieval is limited to:

- `http://`
- the same literal IPv4 host that sent the SSDP response
- bounded response size
- no authentication
- no cross-host redirect following

## Reporting a vulnerability

Please open a GitHub issue describing the affected VoidWalker version, impact, and a minimal reproduction that does not target third-party systems.
