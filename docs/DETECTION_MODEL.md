# Detection model

VoidWalker separates **facts**, **candidates**, and **investigation signals** so that the report does not overstate what a network scan can prove.

## 1. Exposure findings

An exposure finding is a directly observed reachable TCP service.

Examples:

- Telnet is reachable on TCP/23
- ADB/debug is reachable on TCP/5555
- TR-069/CWMP is reachable on TCP/7547
- RTSP is reachable on TCP/554

These findings can be high severity because the service itself creates meaningful attack surface, but they are not automatically labeled as a confirmed vulnerability or compromise.

## 2. Device intelligence

Device intelligence is built from:

- SSDP headers
- same-host UPnP device-description XML
- mDNS/DNS-SD PTR/SRV/TXT/A records
- service names
- collected TCP evidence

The tool may infer a likely device class or vendor from advertised metadata. Explicit manufacturer/model fields are preferred over heuristics.

## 3. Vulnerability candidates

A vulnerability candidate requires a sufficiently specific observed software fingerprint.

### RomPager

If evidence identifies `RomPager/<version>` and the version is `4.34` or earlier, VoidWalker emits a high-confidence candidate for:

- CVE-2014-9222

The report still asks the operator to confirm the actual device model and firmware.

### Boa

If evidence identifies exactly:

```text
Boa/0.94.14rc21
```

VoidWalker emits high-confidence candidates for:

- CVE-2018-21027
- CVE-2018-21028

The tool does not attempt to exploit or trigger either issue.

The signature database is deliberately conservative. A small number of strong matches is preferred over a large number of weak CVE guesses.

## 4. Compromise indicators

### Explicit family strings

If a collected banner or discovery record contains an explicit name associated with an IoT malware family, VoidWalker creates a `compromise-indicator`.

Current strings include:

- Mirai
- Gafgyt / BASHLITE
- Mozi
- Satori

Confidence is `medium` rather than `high` because the text could come from a lab, honeypot, test page, hostname, or descriptive metadata.

### Multiple high-risk management surfaces

If a host exposes at least two services from the following group:

```text
23
2323
5555
7547
37215
52869
```

VoidWalker creates a `compromise-suspicion` indicator with `low` confidence.

This is a prioritization heuristic only. It means the host has a combination of surfaces commonly targeted on embedded systems and deserves follow-up inspection.

## 5. Follow-up after an indicator

A serious investigation should verify, as appropriate:

- exact device manufacturer/model
- firmware version
- vendor advisories
- configuration and access controls
- outbound connections
- DNS behavior
- unexpected listening services
- process list
- file-system changes
- persistence mechanisms
- packet captures
- device reset/reflash guidance from the vendor

VoidWalker intentionally stops before exploitation or destructive validation.

## Confidence levels

**High**  
A specific observed fingerprint maps directly to a documented affected software/version range.

**Medium**  
The evidence is strongly suspicious but can have benign explanations.

**Low**  
A heuristic combination of exposures increases risk but cannot establish a vulnerability or compromise by itself.

## False positives

False positives are possible, especially with:

- proxy banners
- honeypots
- lab systems
- custom firmware
- reverse proxies
- vendor-modified software
- misleading service names

Always preserve the raw evidence and confirm findings before remediation or incident-response decisions.
