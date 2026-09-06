from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sys
import time
from collections.abc import Iterable, Iterator
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass

VERSION = "2.0.0"
DEFAULT_WORKERS = 128
DEFAULT_TIMEOUT = 0.6
DEFAULT_BANNER_TIMEOUT = 0.25
MAX_WORKERS = 256
MAX_HOSTS = 4096


@dataclass(frozen=True, slots=True)
class PortRule:
    port: int
    service: str
    category: str
    severity: str
    note: str
    probe: str = "none"


@dataclass(frozen=True, slots=True)
class Finding:
    host: str
    port: int
    service: str
    category: str
    severity: str
    note: str
    evidence: str | None = None


@dataclass(frozen=True, slots=True)
class ScanReport:
    network: str
    hosts_scanned: int
    ports_scanned: list[int]
    findings: list[Finding]
    duration_ms: int
    interrupted: bool


IOT_RULES: dict[int, PortRule] = {
    21: PortRule(
        21,
        "FTP",
        "legacy-cleartext",
        "medium",
        "FTP commonly exposes credentials and data in cleartext.",
        "passive",
    ),
    23: PortRule(
        23,
        "Telnet",
        "legacy-cleartext",
        "high",
        "Telnet exposes an unauthenticated or weakly protected management surface on many IoT devices.",
        "passive",
    ),
    2323: PortRule(
        2323,
        "Telnet (alternate)",
        "legacy-cleartext",
        "high",
        "Alternate Telnet ports are frequently used by embedded devices.",
        "passive",
    ),
    445: PortRule(
        445,
        "SMB",
        "file-sharing",
        "medium",
        "SMB exposure may be unnecessary on embedded devices; verify that it is expected and patched.",
    ),
    5555: PortRule(
        5555,
        "ADB / debug service",
        "debug-interface",
        "high",
        "Android Debug Bridge or vendor debug services should not normally be exposed to untrusted peers.",
    ),
    5431: PortRule(
        5431,
        "UPnP control / vendor service",
        "management",
        "medium",
        "Vendor management services should be reviewed for necessity and access control.",
    ),
    7547: PortRule(
        7547,
        "TR-069 / CWMP",
        "management",
        "high",
        "CPE management interfaces should be tightly restricted to trusted management networks.",
    ),
    8080: PortRule(
        8080,
        "HTTP alternate / admin UI",
        "web-management",
        "medium",
        "Alternate HTTP ports often host device administration panels.",
        "http",
    ),
    8888: PortRule(
        8888,
        "HTTP alternate",
        "web-management",
        "medium",
        "Alternate HTTP ports may expose management or debug interfaces.",
        "http",
    ),
    37215: PortRule(
        37215,
        "Vendor management service",
        "legacy-vendor-service",
        "high",
        "Historically associated with vulnerable CPE implementations; an open port alone is not proof of compromise.",
    ),
    52869: PortRule(
        52869,
        "Vendor SDK service",
        "legacy-vendor-service",
        "medium",
        "Historically associated with embedded SDK services; verify device model, firmware, and exposure.",
    ),
}

COMMON_RULES: dict[int, PortRule] = {
    **IOT_RULES,
    22: PortRule(
        22,
        "SSH",
        "remote-management",
        "info",
        "SSH may be expected; verify strong authentication and current firmware.",
        "passive",
    ),
    80: PortRule(
        80,
        "HTTP",
        "web-management",
        "info",
        "HTTP may expose a device UI; prefer HTTPS where supported.",
        "http",
    ),
    443: PortRule(
        443,
        "HTTPS",
        "web-management",
        "info",
        "HTTPS management interface detected; review authentication and firmware version.",
    ),
    1883: PortRule(
        1883,
        "MQTT",
        "iot-messaging",
        "medium",
        "MQTT without transport encryption should be restricted and authenticated.",
    ),
    8883: PortRule(
        8883,
        "MQTT over TLS",
        "iot-messaging",
        "info",
        "MQTT over TLS detected; review broker authentication and authorization.",
    ),
}

PROFILES: dict[str, dict[int, PortRule]] = {
    "iot": IOT_RULES,
    "common": COMMON_RULES,
}

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


class ScopeError(ValueError):
    pass


def get_local_ipv4() -> str:
    """Return the preferred local IPv4 address without sending application data."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect(("192.0.2.1", 9))
            address = sock.getsockname()[0]
            return str(ipaddress.IPv4Address(address))
        except OSError:
            return "127.0.0.1"


def default_network() -> ipaddress.IPv4Network:
    local_ip = ipaddress.IPv4Address(get_local_ipv4())
    if local_ip.is_loopback:
        return ipaddress.IPv4Network("127.0.0.1/32")
    return ipaddress.IPv4Interface(f"{local_ip}/24").network


def validate_network(value: str | None) -> ipaddress.IPv4Network:
    network = default_network() if not value else ipaddress.ip_network(value, strict=False)
    if not isinstance(network, ipaddress.IPv4Network):
        raise ScopeError("VoidWalker v2 currently supports IPv4 networks only")
    if network.num_addresses > MAX_HOSTS:
        raise ScopeError(
            f"scope contains {network.num_addresses} addresses; maximum is {MAX_HOSTS}"
        )
    if not (network.is_private or network.is_loopback or network.is_link_local):
        raise ScopeError(
            "public Internet ranges are intentionally out of scope; "
            "use a private, loopback, or link-local network"
        )
    return network


def parse_ports(spec: str) -> list[int]:
    ports: set[int] = set()
    for token in spec.split(","):
        token = token.strip()
        if not token:
            raise ValueError("empty port token")
        if "-" in token:
            if token.count("-") != 1:
                raise ValueError(f"invalid port range: {token}")
            start_text, end_text = token.split("-", 1)
            start = _parse_port(start_text)
            end = _parse_port(end_text)
            if start > end:
                raise ValueError(f"reversed port range: {token}")
            ports.update(range(start, end + 1))
        else:
            ports.add(_parse_port(token))
    if not ports:
        raise ValueError("no ports selected")
    return sorted(ports)


def _parse_port(value: str) -> int:
    try:
        port = int(value, 10)
    except ValueError as exc:
        raise ValueError(f"invalid port: {value!r}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"port out of range: {port}")
    return port


def iter_hosts(network: ipaddress.IPv4Network) -> Iterator[ipaddress.IPv4Address]:
    if network.prefixlen == 32:
        yield network.network_address
        return
    yield from network.hosts()


def rules_for(profile: str, custom_ports: list[int] | None) -> dict[int, PortRule]:
    if custom_ports is None:
        return dict(PROFILES[profile])
    known = COMMON_RULES
    return {
        port: known.get(
            port,
            PortRule(
                port,
                "unknown",
                "custom",
                "info",
                "Custom TCP port selected by the operator.",
            ),
        )
        for port in custom_ports
    }


def _sanitize_banner(data: bytes, limit: int = 160) -> str | None:
    if not data:
        return None
    text = data.decode("utf-8", errors="replace").replace("\r", " ").replace("\n", " ")
    text = " ".join(text.split())
    return text[:limit] or None


def _probe_socket(
    sock: socket.socket, host: str, rule: PortRule, banner_timeout: float
) -> str | None:
    if banner_timeout <= 0 or rule.probe == "none":
        return None
    sock.settimeout(banner_timeout)
    try:
        if rule.probe == "http":
            request = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: VoidWalker/{VERSION}\r\n\r\n"
            sock.sendall(request.encode("ascii", errors="ignore"))
        return _sanitize_banner(sock.recv(512))
    except (OSError, TimeoutError):
        return None


def scan_endpoint(
    host: str, rule: PortRule, timeout: float, banner_timeout: float
) -> Finding | None:
    try:
        with socket.create_connection((host, rule.port), timeout=timeout) as sock:
            evidence = _probe_socket(sock, host, rule, banner_timeout)
            return Finding(
                host=host,
                port=rule.port,
                service=rule.service,
                category=rule.category,
                severity=rule.severity,
                note=rule.note,
                evidence=evidence,
            )
    except (ConnectionError, OSError, TimeoutError):
        return None


def _tasks(
    hosts: Iterable[ipaddress.IPv4Address], rules: dict[int, PortRule]
) -> Iterator[tuple[str, PortRule]]:
    for host in hosts:
        host_text = str(host)
        for port in sorted(rules):
            yield host_text, rules[port]


def run_scan(
    network: ipaddress.IPv4Network,
    rules: dict[int, PortRule],
    *,
    workers: int,
    timeout: float,
    banner_timeout: float,
) -> ScanReport:
    started = time.perf_counter()
    findings: list[Finding] = []
    interrupted = False
    task_iter = iter(_tasks(iter_hosts(network), rules))
    pending: dict[Future[Finding | None], None] = {}
    window = max(workers * 4, workers)

    def submit_next(executor: ThreadPoolExecutor) -> bool:
        try:
            host, rule = next(task_iter)
        except StopIteration:
            return False
        pending[executor.submit(scan_endpoint, host, rule, timeout, banner_timeout)] = None
        return True

    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="voidwalker") as executor:
        for _ in range(window):
            if not submit_next(executor):
                break
        try:
            while pending:
                done, _ = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    pending.pop(future, None)
                    result = future.result()
                    if result is not None:
                        findings.append(result)
                    submit_next(executor)
        except KeyboardInterrupt:
            interrupted = True
            for future in pending:
                future.cancel()

    findings.sort(
        key=lambda item: (
            ipaddress.ip_address(item.host),
            SEVERITY_ORDER.get(item.severity, 99),
            item.port,
        )
    )
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    return ScanReport(
        network=str(network),
        hosts_scanned=sum(1 for _ in iter_hosts(network)),
        ports_scanned=sorted(rules),
        findings=findings,
        duration_ms=elapsed_ms,
        interrupted=interrupted,
    )


def report_to_json(report: ScanReport) -> str:
    payload = {
        "tool": "VoidWalker",
        "version": VERSION,
        "network": report.network,
        "hosts_scanned": report.hosts_scanned,
        "ports_scanned": report.ports_scanned,
        "findings": [asdict(item) for item in report.findings],
        "duration_ms": report.duration_ms,
        "interrupted": report.interrupted,
    }
    return json.dumps(payload, indent=2, sort_keys=False)


def print_report(report: ScanReport) -> None:
    print(f"VoidWalker v{VERSION} - local IoT exposure auditor")
    print(f"Scope: {report.network}")
    print(
        f"Hosts: {report.hosts_scanned} | TCP ports: {len(report.ports_scanned)} | "
        f"Findings: {len(report.findings)}"
    )
    print("-" * 76)

    if not report.findings:
        print("No selected TCP services were reachable in this scope.")
    else:
        for finding in report.findings:
            print(
                f"[{finding.severity.upper():6}] {finding.host}:{finding.port:<5} "
                f"{finding.service}  ({finding.category})"
            )
            print(f"         {finding.note}")
            if finding.evidence:
                print(f"         evidence: {finding.evidence}")

    print("-" * 76)
    suffix = " (interrupted)" if report.interrupted else ""
    print(f"Finished in {report.duration_ms / 1000:.2f}s{suffix}")
    print("Open ports are exposure signals, not proof of vulnerability or compromise.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Concurrent TCP exposure auditor for private/local IPv4 networks. "
            "It identifies reachable management and legacy services without exploitation."
        )
    )
    parser.add_argument("-n", "--network", help="private IPv4 CIDR (default: detected local /24)")
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILES),
        default="iot",
        help="built-in TCP port profile",
    )
    parser.add_argument("-p", "--ports", help="custom TCP ports/ranges, e.g. 22,80,443,8000-8010")
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"concurrent workers (1-{MAX_WORKERS})",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="TCP connect timeout in seconds",
    )
    parser.add_argument(
        "--banner-timeout",
        type=float,
        default=DEFAULT_BANNER_TIMEOUT,
        help="optional evidence-read timeout in seconds",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON only")
    parser.add_argument("--version", action="version", version=f"VoidWalker v{VERSION}")
    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not 1 <= args.workers <= MAX_WORKERS:
        parser.error(f"--workers must be between 1 and {MAX_WORKERS}")
    if not 0.05 <= args.timeout <= 5.0:
        parser.error("--timeout must be between 0.05 and 5.0 seconds")
    if not 0 <= args.banner_timeout <= 2.0:
        parser.error("--banner-timeout must be between 0 and 2.0 seconds")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        network = validate_network(args.network)
        custom_ports = parse_ports(args.ports) if args.ports else None
        rules = rules_for(args.profile, custom_ports)
    except (ScopeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = run_scan(
        network,
        rules,
        workers=args.workers,
        timeout=args.timeout,
        banner_timeout=args.banner_timeout,
    )
    if args.json:
        print(report_to_json(report))
    else:
        print_report(report)
    return 130 if report.interrupted else 0


if __name__ == "__main__":
    raise SystemExit(main())
