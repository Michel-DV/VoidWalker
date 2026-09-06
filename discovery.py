from __future__ import annotations

import http.client
import ipaddress
import socket
import struct
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, replace
from urllib.parse import urlsplit

SSDP_ADDRESS = ("239.255.255.250", 1900)
MDNS_ADDRESS = ("224.0.0.251", 5353)
MAX_DESCRIPTION_BYTES = 65536
MDNS_SERVICE_TYPES = (
    "_http._tcp.local",
    "_https._tcp.local",
    "_rtsp._tcp.local",
    "_mqtt._tcp.local",
    "_ssh._tcp.local",
    "_ipp._tcp.local",
    "_printer._tcp.local",
    "_googlecast._tcp.local",
    "_hap._tcp.local",
)


@dataclass(frozen=True, slots=True)
class DiscoveryRecord:
    host: str
    protocol: str
    service: str
    name: str | None = None
    location: str | None = None
    server: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    device_type: str | None = None
    metadata: tuple[tuple[str, str], ...] = ()


def _in_scope(host: str, network: ipaddress.IPv4Network) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return isinstance(address, ipaddress.IPv4Address) and address in network


def parse_ssdp_response(data: bytes, host: str) -> DiscoveryRecord | None:
    text = data.decode("latin-1", errors="replace")
    lines = [line.strip() for line in text.replace("\r\n", "\n").split("\n") if line.strip()]
    if not lines:
        return None

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()

    service = headers.get("st") or headers.get("nt") or "ssdp"
    name = headers.get("usn")
    metadata = tuple(
        sorted(
            (key, value)
            for key, value in headers.items()
            if key in {"cache-control", "ext", "nt", "st", "usn"}
        )
    )
    return DiscoveryRecord(
        host=host,
        protocol="ssdp",
        service=service,
        name=name,
        location=headers.get("location"),
        server=headers.get("server"),
        metadata=metadata,
    )


def _description_path(location: str, expected_host: str) -> tuple[str, int, str] | None:
    try:
        parts = urlsplit(location)
    except ValueError:
        return None
    if parts.scheme.lower() != "http" or parts.username or parts.password:
        return None
    if parts.hostname != expected_host:
        return None
    try:
        port = parts.port or 80
    except ValueError:
        return None
    if not 1 <= port <= 65535:
        return None
    path = parts.path or "/"
    if parts.query:
        path += f"?{parts.query}"
    return expected_host, port, path


def parse_device_description(data: bytes) -> dict[str, str]:
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return {}

    wanted = {
        "friendlyname": "name",
        "manufacturer": "manufacturer",
        "modelname": "model",
        "modelnumber": "model_number",
        "devicetype": "device_type",
    }
    result: dict[str, str] = {}
    for element in root.iter():
        local_name = element.tag.rsplit("}", 1)[-1].lower()
        target = wanted.get(local_name)
        if target and element.text:
            value = " ".join(element.text.split())[:160]
            if value and target not in result:
                result[target] = value
    return result


def fetch_device_description(record: DiscoveryRecord, timeout: float) -> DiscoveryRecord:
    if not record.location:
        return record
    target = _description_path(record.location, record.host)
    if target is None:
        return record
    host, port, path = target
    conn = http.client.HTTPConnection(host, port, timeout=max(0.1, timeout))
    try:
        conn.request(
            "GET",
            path,
            headers={
                "Host": host,
                "User-Agent": "VoidWalker/2.1",
                "Accept": "text/xml, application/xml",
                "Connection": "close",
            },
        )
        response = conn.getresponse()
        if not 200 <= response.status < 300:
            return record
        data = response.read(MAX_DESCRIPTION_BYTES + 1)
        if len(data) > MAX_DESCRIPTION_BYTES:
            return record
    except (OSError, http.client.HTTPException):
        return record
    finally:
        conn.close()

    details = parse_device_description(data)
    metadata = dict(record.metadata)
    if details.get("model_number"):
        metadata["model_number"] = details["model_number"]
    return replace(
        record,
        name=details.get("name") or record.name,
        manufacturer=details.get("manufacturer"),
        model=details.get("model"),
        device_type=details.get("device_type"),
        metadata=tuple(sorted(metadata.items())),
    )


def discover_ssdp(
    network: ipaddress.IPv4Network,
    *,
    timeout: float,
    fetch_descriptions: bool,
) -> list[DiscoveryRecord]:
    request = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).encode("ascii")
    records: dict[tuple[str, str, str | None], DiscoveryRecord] = {}
    deadline = time.monotonic() + max(0.05, timeout)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(min(0.2, max(0.05, timeout)))
            sock.sendto(request, SSDP_ADDRESS)
            while time.monotonic() < deadline:
                try:
                    data, addr = sock.recvfrom(65535)
                except TimeoutError:
                    continue
                except OSError:
                    break
                host = addr[0]
                if not _in_scope(host, network):
                    continue
                record = parse_ssdp_response(data, host)
                if record is None:
                    continue
                key = (record.host, record.service, record.location)
                records[key] = record
    except OSError:
        return []

    result = list(records.values())
    if fetch_descriptions:
        result = [fetch_device_description(record, min(timeout, 0.8)) for record in result]
    result.sort(key=lambda item: (ipaddress.ip_address(item.host), item.protocol, item.service))
    return result


def _encode_dns_name(name: str) -> bytes:
    labels = name.rstrip(".").split(".")
    output = bytearray()
    for label in labels:
        raw = label.encode("utf-8")
        if not raw or len(raw) > 63:
            raise ValueError(f"invalid DNS label: {label!r}")
        output.append(len(raw))
        output.extend(raw)
    output.append(0)
    return bytes(output)


def build_mdns_query(service_types: tuple[str, ...] = MDNS_SERVICE_TYPES) -> bytes:
    header = struct.pack("!HHHHHH", 0, 0, len(service_types), 0, 0, 0)
    questions = b"".join(
        _encode_dns_name(service) + struct.pack("!HH", 12, 0x8001) for service in service_types
    )
    return header + questions


def _decode_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    cursor = offset
    next_offset: int | None = None
    seen: set[int] = set()

    while True:
        if cursor >= len(data):
            raise ValueError("truncated DNS name")
        if cursor in seen:
            raise ValueError("DNS compression loop")
        seen.add(cursor)

        length = data[cursor]
        if length == 0:
            cursor += 1
            return ".".join(labels), next_offset or cursor
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(data):
                raise ValueError("truncated DNS pointer")
            pointer = ((length & 0x3F) << 8) | data[cursor + 1]
            if pointer >= len(data):
                raise ValueError("invalid DNS pointer")
            if next_offset is None:
                next_offset = cursor + 2
            cursor = pointer
            continue
        if length & 0xC0:
            raise ValueError("unsupported DNS label encoding")
        cursor += 1
        end = cursor + length
        if end > len(data):
            raise ValueError("truncated DNS label")
        labels.append(data[cursor:end].decode("utf-8", errors="replace"))
        cursor = end


def _parse_txt(data: bytes) -> tuple[str, ...]:
    values: list[str] = []
    offset = 0
    while offset < len(data):
        length = data[offset]
        offset += 1
        end = offset + length
        if end > len(data):
            break
        value = data[offset:end].decode("utf-8", errors="replace")
        values.append(" ".join(value.split())[:160])
        offset = end
    return tuple(value for value in values if value)


def parse_mdns_response(
    packet: bytes,
    network: ipaddress.IPv4Network,
) -> list[DiscoveryRecord]:
    if len(packet) < 12:
        return []
    try:
        _, _, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])
        offset = 12
        for _ in range(qdcount):
            _, offset = _decode_dns_name(packet, offset)
            if offset + 4 > len(packet):
                return []
            offset += 4

        ptrs: dict[str, list[str]] = {}
        srvs: dict[str, tuple[int, str]] = {}
        txts: dict[str, tuple[str, ...]] = {}
        addresses: dict[str, str] = {}

        for _ in range(ancount + nscount + arcount):
            name, offset = _decode_dns_name(packet, offset)
            if offset + 10 > len(packet):
                return []
            rr_type, _, _, rdlength = struct.unpack("!HHIH", packet[offset : offset + 10])
            offset += 10
            rdata_offset = offset
            end = offset + rdlength
            if end > len(packet):
                return []

            if rr_type == 1 and rdlength == 4:
                addresses[name.lower()] = socket.inet_ntoa(packet[offset:end])
            elif rr_type == 12:
                target, _ = _decode_dns_name(packet, rdata_offset)
                ptrs.setdefault(name.lower(), []).append(target)
            elif rr_type == 33 and rdlength >= 6:
                _, _, port = struct.unpack("!HHH", packet[offset : offset + 6])
                target, _ = _decode_dns_name(packet, offset + 6)
                srvs[name.lower()] = (port, target)
            elif rr_type == 16:
                txts[name.lower()] = _parse_txt(packet[offset:end])
            offset = end
    except (ValueError, struct.error, OSError):
        return []

    instance_services: dict[str, str] = {}
    for service, instances in ptrs.items():
        for instance in instances:
            instance_services[instance.lower()] = service

    records: list[DiscoveryRecord] = []
    for instance_lower, (port, target) in srvs.items():
        host = addresses.get(target.lower())
        if not host or not _in_scope(host, network):
            continue
        service = instance_services.get(instance_lower, "mdns-service")
        display_name = instance_lower
        suffix = f".{service}"
        if display_name.endswith(suffix):
            display_name = display_name[: -len(suffix)]
        metadata_items = [("hostname", target), ("port", str(port))]
        metadata_items.extend(("txt", value) for value in txts.get(instance_lower, ()))
        records.append(
            DiscoveryRecord(
                host=host,
                protocol="mdns",
                service=service,
                name=display_name or None,
                metadata=tuple(metadata_items),
            )
        )

    records.sort(key=lambda item: (ipaddress.ip_address(item.host), item.service, item.name or ""))
    return records


def discover_mdns(
    network: ipaddress.IPv4Network,
    *,
    timeout: float,
) -> list[DiscoveryRecord]:
    packet = build_mdns_query()
    deadline = time.monotonic() + max(0.05, timeout)
    records: dict[tuple[str, str, str | None], DiscoveryRecord] = {}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(min(0.2, max(0.05, timeout)))
            sock.sendto(packet, MDNS_ADDRESS)
            while time.monotonic() < deadline:
                try:
                    data, _ = sock.recvfrom(65535)
                except TimeoutError:
                    continue
                except OSError:
                    break
                for record in parse_mdns_response(data, network):
                    records[(record.host, record.service, record.name)] = record
    except OSError:
        return []
    return sorted(
        records.values(),
        key=lambda item: (ipaddress.ip_address(item.host), item.protocol, item.service),
    )


def discover_devices(
    network: ipaddress.IPv4Network,
    *,
    mode: str,
    timeout: float,
    fetch_descriptions: bool = True,
) -> list[DiscoveryRecord]:
    if mode == "off":
        return []
    records: list[DiscoveryRecord] = []
    if mode in {"ssdp", "all"}:
        records.extend(
            discover_ssdp(
                network,
                timeout=timeout,
                fetch_descriptions=fetch_descriptions,
            )
        )
    if mode in {"mdns", "all"}:
        records.extend(discover_mdns(network, timeout=timeout))

    unique: dict[tuple[str, str, str, str | None], DiscoveryRecord] = {}
    for record in records:
        unique[(record.host, record.protocol, record.service, record.name)] = record
    return sorted(
        unique.values(),
        key=lambda item: (ipaddress.ip_address(item.host), item.protocol, item.service),
    )
