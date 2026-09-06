# Security policy

VoidWalker is intentionally scoped as a local/private-network TCP exposure auditor.

## Security boundaries

- IPv4 only in v2.0
- private, loopback, or link-local targets only
- maximum scope: 4096 addresses
- TCP connect scanning only
- no raw packets or stealth scanning
- no credential attacks
- no exploitation
- no persistence or remote code execution
- no vulnerability claim based solely on an open port

The built-in service notes are triage hints. They are not proof that a host is vulnerable, infected, or compromised.

## Reporting a vulnerability

Please open a GitHub issue describing the affected version, impact, and a minimal reproduction that does not target third-party systems.
