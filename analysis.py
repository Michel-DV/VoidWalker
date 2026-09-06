from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Protocol

from discovery import DiscoveryRecord


class FindingLike(Protocol):
    host: str
    port: int
    service: str
    category: str
    severity: str
    evidence: str | None


@dataclass(frozen=True, slots=True)
class DeviceProfile:
    host: str
    names: tuple[str, ...] = ()
    manufacturer: str | None = None
    model: str | None = None
    device_type: str | None = None
    sources: tuple[str, ...] = ()
    services: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Indicator:
    host: str
    kind: str
    severity: str
    confidence: str
    title: str
    rationale: str
    evidence: tuple[str, ...] = ()
    references: tuple[str, ...] = ()


VENDOR_PATTERNS: tuple[tuple[str, str], ...] = (
    ("hikvision", "Hikvision"),
    ("dahua", "Dahua"),
    ("axis", "Axis"),
    ("reolink", "Reolink"),
    ("tp-link", "TP-Link"),
    ("tplink", "TP-Link"),
    ("ubiquiti", "Ubiquiti"),
    ("sonos", "Sonos"),
    ("philips", "Philips"),
    ("hue", "Philips Hue"),
    ("xiaomi", "Xiaomi"),
    ("tuya", "Tuya"),
    ("espressif", "Espressif"),
    ("esp32", "Espressif"),
    ("raspberry", "Raspberry Pi"),
    ("synology", "Synology"),
    ("samsung", "Samsung"),
    ("amazon", "Amazon"),
    ("google", "Google"),
    ("nest", "Google Nest"),
    ("apple", "Apple"),
)

DEVICE_TYPE_PATTERNS: tuple[tuple[str, str], ...] = (
    ("internetgatewaydevice", "router/cpe"),
    ("wandevice", "router/cpe"),
    ("router", "router/cpe"),
    ("gateway", "router/cpe"),
    ("camera", "camera"),
    ("onvif", "camera"),
    ("rtsp", "camera/media"),
    ("nvr", "video recorder"),
    ("printer", "printer"),
    ("_ipp._tcp", "printer"),
    ("mediarenderer", "media device"),
    ("mediaserver", "media device"),
    ("googlecast", "media device"),
    ("sonos", "media device"),
    ("_hap._tcp", "smart-home accessory"),
    ("homekit", "smart-home accessory"),
    ("mqtt", "iot gateway/broker"),
    ("adb", "android/embedded device"),
    ("tr-069", "router/cpe"),
    ("cwmp", "router/cpe"),
)

MALWARE_FAMILY_PATTERNS: tuple[tuple[str, str], ...] = (
    ("mirai", "Mirai"),
    ("gafgyt", "Gafgyt/BASHLITE"),
    ("bashlite", "Gafgyt/BASHLITE"),
    ("mozi", "Mozi"),
    ("satori", "Satori"),
)

HIGH_RISK_PORTS = {23, 2323, 5555, 7547, 37215, 52869}


def _joined_text(record: DiscoveryRecord) -> str:
    fields = [
        record.service,
        record.name or "",
        record.location or "",
        record.server or "",
        record.manufacturer or "",
        record.model or "",
        record.device_type or "",
    ]
    fields.extend(value for _, value in record.metadata)
    return " ".join(fields)


def _infer_vendor(text: str) -> str | None:
    lowered = text.lower()
    for pattern, vendor in VENDOR_PATTERNS:
        if pattern in lowered:
            return vendor
    return None


def _infer_device_type(text: str) -> str | None:
    lowered = text.lower()
    for pattern, device_type in DEVICE_TYPE_PATTERNS:
        if pattern in lowered:
            return device_type
    return None


def build_device_profiles(
    findings: list[FindingLike],
    discovery_records: list[DiscoveryRecord],
) -> list[DeviceProfile]:
    finding_by_host: dict[str, list[FindingLike]] = defaultdict(list)
    discovery_by_host: dict[str, list[DiscoveryRecord]] = defaultdict(list)
    for finding in findings:
        finding_by_host[finding.host].append(finding)
    for record in discovery_records:
        discovery_by_host[record.host].append(record)

    hosts = sorted(
        set(finding_by_host) | set(discovery_by_host),
        key=ipaddress.ip_address,
    )
    profiles: list[DeviceProfile] = []

    for host in hosts:
        records = discovery_by_host[host]
        host_findings = finding_by_host[host]
        names = sorted({record.name for record in records if record.name})
        sources = sorted({record.protocol for record in records})
        services = sorted(
            {finding.service for finding in host_findings} | {record.service for record in records}
        )

        manufacturer = next(
            (record.manufacturer for record in records if record.manufacturer),
            None,
        )
        model = next((record.model for record in records if record.model), None)
        explicit_device_type = next(
            (record.device_type for record in records if record.device_type),
            None,
        )

        evidence_text = " ".join(
            [_joined_text(record) for record in records]
            + [f"{finding.service} {finding.evidence or ''}" for finding in host_findings]
        )
        manufacturer = manufacturer or _infer_vendor(evidence_text)
        device_type = _infer_device_type(explicit_device_type or "") or _infer_device_type(
            evidence_text
        )
        if device_type is None and explicit_device_type:
            device_type = explicit_device_type

        profiles.append(
            DeviceProfile(
                host=host,
                names=tuple(names),
                manufacturer=manufacturer,
                model=model,
                device_type=device_type,
                sources=tuple(sources),
                services=tuple(services),
            )
        )
    return profiles


def _version_tuple(value: str) -> tuple[int, ...] | None:
    if not re.fullmatch(r"\d+(?:\.\d+)*", value):
        return None
    return tuple(int(part) for part in value.split("."))


def _rompager_indicator(host: str, text: str) -> Indicator | None:
    match = re.search(r"rompager/(\d+(?:\.\d+)+)", text, flags=re.IGNORECASE)
    if not match:
        return None
    version = _version_tuple(match.group(1))
    if version is None or version > (4, 34):
        return None
    evidence = match.group(0)
    return Indicator(
        host=host,
        kind="vulnerability-candidate",
        severity="high",
        confidence="high",
        title="RomPager version falls in the Misfortune Cookie affected range",
        rationale=(
            "The observed RomPager version is 4.34 or earlier. That version range is associated "
            "with CVE-2014-9222. Confirm the device model and firmware before treating the host as "
            "definitively vulnerable."
        ),
        evidence=(evidence,),
        references=("CVE-2014-9222",),
    )


def _boa_indicator(host: str, text: str) -> Indicator | None:
    match = re.search(r"boa/0\.94\.14rc21\b", text, flags=re.IGNORECASE)
    if not match:
        return None
    return Indicator(
        host=host,
        kind="vulnerability-candidate",
        severity="high",
        confidence="high",
        title="Legacy Boa 0.94.14rc21 web server fingerprint",
        rationale=(
            "Boa 0.94.14rc21 is an end-of-life embedded web server version with published "
            "vulnerabilities. Confirm the exact device integration and firmware because some "
            "issues depend on vendor-specific CGI components."
        ),
        evidence=(match.group(0),),
        references=("CVE-2018-21027", "CVE-2018-21028"),
    )


def _malware_indicators(host: str, text: str) -> list[Indicator]:
    lowered = text.lower()
    indicators: list[Indicator] = []
    for pattern, family in MALWARE_FAMILY_PATTERNS:
        if pattern not in lowered:
            continue
        indicators.append(
            Indicator(
                host=host,
                kind="compromise-indicator",
                severity="critical",
                confidence="medium",
                title=f"{family} family string observed in device/service evidence",
                rationale=(
                    "A malware-family name appeared in a service banner or discovery record. "
                    "This is a strong investigation lead, but it can also occur in lab systems, "
                    "honeypots, or descriptive text and is not standalone proof of infection."
                ),
                evidence=(family,),
            )
        )
    return indicators


def analyze_indicators(
    findings: list[FindingLike],
    discovery_records: list[DiscoveryRecord],
) -> list[Indicator]:
    findings_by_host: dict[str, list[FindingLike]] = defaultdict(list)
    records_by_host: dict[str, list[DiscoveryRecord]] = defaultdict(list)
    for finding in findings:
        findings_by_host[finding.host].append(finding)
    for record in discovery_records:
        records_by_host[record.host].append(record)

    hosts = sorted(
        set(findings_by_host) | set(records_by_host),
        key=ipaddress.ip_address,
    )
    indicators: list[Indicator] = []
    for host in hosts:
        host_findings = findings_by_host[host]
        host_records = records_by_host[host]
        evidence_parts = [finding.evidence or "" for finding in host_findings]
        evidence_parts.extend(_joined_text(record) for record in host_records)
        text = " ".join(evidence_parts)

        for candidate in (_rompager_indicator(host, text), _boa_indicator(host, text)):
            if candidate is not None:
                indicators.append(candidate)

        indicators.extend(_malware_indicators(host, text))

        risky = sorted({finding.port for finding in host_findings} & HIGH_RISK_PORTS)
        if len(risky) >= 2:
            indicators.append(
                Indicator(
                    host=host,
                    kind="compromise-suspicion",
                    severity="high",
                    confidence="low",
                    title="Multiple botnet-targeted management surfaces are reachable",
                    rationale=(
                        "Several services commonly targeted on embedded devices are reachable at "
                        "the same host. This increases compromise risk and merits firmware, "
                        "process, "
                        "DNS, and traffic inspection, but it is not proof that malware is present."
                    ),
                    evidence=tuple(f"tcp/{port}" for port in risky),
                )
            )

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    confidence_order = {"high": 0, "medium": 1, "low": 2}
    indicators.sort(
        key=lambda item: (
            ipaddress.ip_address(item.host),
            severity_order.get(item.severity, 99),
            confidence_order.get(item.confidence, 99),
            item.title,
        )
    )
    return indicators
