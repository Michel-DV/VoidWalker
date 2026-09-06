from __future__ import annotations

import contextlib
import io
import json
import socket
import threading
import unittest
from unittest.mock import patch

import VoidWalker as vw


class PortParsingTests(unittest.TestCase):
    def test_parse_ports_deduplicates_and_sorts(self) -> None:
        self.assertEqual(vw.parse_ports("443,80,80,1000-1002"), [80, 443, 1000, 1001, 1002])

    def test_parse_ports_rejects_bad_values(self) -> None:
        for value in ("", "0", "65536", "10-1", "abc", "1--2"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    vw.parse_ports(value)


class ScopeTests(unittest.TestCase):
    def test_accepts_private_and_loopback_scopes(self) -> None:
        self.assertEqual(str(vw.validate_network("192.168.10.2/24")), "192.168.10.0/24")
        self.assertEqual(str(vw.validate_network("127.0.0.1/32")), "127.0.0.1/32")

    def test_rejects_public_and_oversized_scopes(self) -> None:
        with self.assertRaises(vw.ScopeError):
            vw.validate_network("8.8.8.0/24")
        with self.assertRaises(vw.ScopeError):
            vw.validate_network("10.0.0.0/8")


class ScannerTests(unittest.TestCase):
    def test_open_local_port_is_reported(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def server() -> None:
            conn, _ = listener.accept()
            with conn:
                conn.sendall(b"LAB-BANNER\r\n")
            listener.close()

        thread = threading.Thread(target=server, daemon=True)
        thread.start()

        rules = {port: vw.PortRule(port, "lab", "custom", "info", "local test", "passive")}
        report = vw.run_scan(
            vw.validate_network("127.0.0.1/32"),
            rules,
            workers=4,
            timeout=0.5,
            banner_timeout=0.5,
        )
        thread.join(timeout=2)
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].port, port)
        self.assertIn("LAB-BANNER", report.findings[0].evidence or "")

    def test_http_probe_collects_status_line(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def server() -> None:
            conn, _ = listener.accept()
            with conn:
                conn.recv(1024)
                conn.sendall(b"HTTP/1.0 200 OK\r\nServer: VoidLab\r\n\r\n")
            listener.close()

        thread = threading.Thread(target=server, daemon=True)
        thread.start()
        rule = vw.PortRule(port, "http-lab", "custom", "info", "local test", "http")
        finding = vw.scan_endpoint("127.0.0.1", rule, 0.5, 0.5)
        thread.join(timeout=2)
        self.assertIsNotNone(finding)
        self.assertIn("HTTP/1.0 200 OK", finding.evidence or "")


class OutputTests(unittest.TestCase):
    def test_json_output_is_machine_readable(self) -> None:
        report = vw.ScanReport(
            network="127.0.0.1/32",
            hosts_scanned=1,
            ports_scanned=[80],
            findings=[],
            duration_ms=12,
            interrupted=False,
        )
        payload = json.loads(vw.report_to_json(report))
        self.assertEqual(payload["tool"], "VoidWalker")
        self.assertEqual(payload["hosts_scanned"], 1)
        self.assertEqual(payload["version"], "2.1.0")
        self.assertEqual(payload["devices"], [])
        self.assertEqual(payload["indicators"], [])

    def test_main_rejects_public_scope(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            rc = vw.main(["--network", "8.8.8.0/24", "--json"])
        self.assertEqual(rc, 2)
        self.assertIn("public Internet ranges", stderr.getvalue())

    def test_default_network_falls_back_to_loopback(self) -> None:
        with patch("VoidWalker.get_local_ipv4", return_value="127.0.0.1"):
            self.assertEqual(str(vw.default_network()), "127.0.0.1/32")

    def test_discovery_can_be_disabled(self) -> None:
        report = vw.ScanReport(
            network="127.0.0.1/32",
            hosts_scanned=1,
            ports_scanned=[],
            findings=[],
            duration_ms=1,
            interrupted=False,
        )
        enriched = vw.enrich_report(
            report,
            vw.validate_network("127.0.0.1/32"),
            discovery_mode="off",
            discovery_timeout=0.1,
            fetch_descriptions=False,
        )
        self.assertEqual(enriched.discovery_records, [])


if __name__ == "__main__":
    unittest.main()
