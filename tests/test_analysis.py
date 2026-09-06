from __future__ import annotations

import unittest

import VoidWalker as vw
from analysis import analyze_indicators, build_device_profiles
from discovery import DiscoveryRecord


class DeviceProfileTests(unittest.TestCase):
    def test_infers_camera_vendor_and_type(self) -> None:
        finding = vw.Finding(
            host="192.168.1.50",
            port=554,
            service="RTSP",
            category="media-streaming",
            severity="medium",
            note="test",
            evidence="RTSP/1.0 200 OK Server: Hikvision",
        )
        record = DiscoveryRecord(
            host="192.168.1.50",
            protocol="mdns",
            service="_rtsp._tcp.local",
            name="front-camera",
        )
        profiles = build_device_profiles([finding], [record])
        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0].manufacturer, "Hikvision")
        self.assertIn("camera", profiles[0].device_type or "")


class IndicatorTests(unittest.TestCase):
    def test_rompager_affected_version_maps_to_cve(self) -> None:
        finding = vw.Finding(
            host="192.168.1.1",
            port=80,
            service="HTTP",
            category="web-management",
            severity="info",
            note="test",
            evidence="HTTP/1.1 200 OK Server: RomPager/4.07",
        )
        indicators = analyze_indicators([finding], [])
        self.assertTrue(any("CVE-2014-9222" in item.references for item in indicators))
        self.assertTrue(any(item.confidence == "high" for item in indicators))

    def test_boa_legacy_fingerprint_maps_to_cves(self) -> None:
        finding = vw.Finding(
            host="192.168.1.2",
            port=80,
            service="HTTP",
            category="web-management",
            severity="info",
            note="test",
            evidence="HTTP/1.0 200 OK Server: Boa/0.94.14rc21",
        )
        indicators = analyze_indicators([finding], [])
        refs = {ref for item in indicators for ref in item.references}
        self.assertIn("CVE-2018-21027", refs)
        self.assertIn("CVE-2018-21028", refs)

    def test_explicit_malware_family_string_is_triaged(self) -> None:
        finding = vw.Finding(
            host="192.168.1.3",
            port=23,
            service="Telnet",
            category="legacy-cleartext",
            severity="high",
            note="test",
            evidence="lab banner: MIRAI sample",
        )
        indicators = analyze_indicators([finding], [])
        self.assertTrue(any(item.kind == "compromise-indicator" for item in indicators))
        self.assertTrue(any("Mirai" in item.title for item in indicators))

    def test_multiple_high_risk_surfaces_create_low_confidence_suspicion(self) -> None:
        findings = [
            vw.Finding("192.168.1.4", 23, "Telnet", "legacy", "high", "test"),
            vw.Finding("192.168.1.4", 5555, "ADB", "debug", "high", "test"),
        ]
        indicators = analyze_indicators(findings, [])
        suspicion = [item for item in indicators if item.kind == "compromise-suspicion"]
        self.assertEqual(len(suspicion), 1)
        self.assertEqual(suspicion[0].confidence, "low")
        self.assertIn("tcp/23", suspicion[0].evidence)
        self.assertIn("tcp/5555", suspicion[0].evidence)


if __name__ == "__main__":
    unittest.main()
