from __future__ import annotations

import ipaddress
import struct
import unittest

import discovery


def rr(name: str, rr_type: int, rdata: bytes, ttl: int = 120) -> bytes:
    return (
        discovery._encode_dns_name(name) + struct.pack("!HHIH", rr_type, 1, ttl, len(rdata)) + rdata
    )


class SSDPTests(unittest.TestCase):
    def test_parse_ssdp_response(self) -> None:
        packet = (
            b"HTTP/1.1 200 OK\r\n"
            b"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
            b"USN: uuid:router::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
            b"SERVER: Linux/3.4 UPnP/1.0 RomPager/4.07\r\n"
            b"LOCATION: http://192.168.1.1:80/rootDesc.xml\r\n\r\n"
        )
        record = discovery.parse_ssdp_response(packet, "192.168.1.1")
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record.protocol, "ssdp")
        self.assertIn("InternetGatewayDevice", record.service)
        self.assertIn("RomPager/4.07", record.server or "")

    def test_parse_device_description(self) -> None:
        xml = b"""<?xml version='1.0'?>
        <root xmlns='urn:schemas-upnp-org:device-1-0'>
          <device>
            <friendlyName>Living Room Camera</friendlyName>
            <manufacturer>AcmeCam</manufacturer>
            <modelName>XC-1</modelName>
            <modelNumber>42</modelNumber>
            <deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType>
          </device>
        </root>"""
        details = discovery.parse_device_description(xml)
        self.assertEqual(details["name"], "Living Room Camera")
        self.assertEqual(details["manufacturer"], "AcmeCam")
        self.assertEqual(details["model"], "XC-1")
        self.assertEqual(details["model_number"], "42")

    def test_description_url_must_stay_on_same_host(self) -> None:
        self.assertIsNotNone(
            discovery._description_path(
                "http://192.168.1.20:8080/device.xml",
                "192.168.1.20",
            )
        )
        self.assertIsNone(
            discovery._description_path(
                "http://192.168.1.99/device.xml",
                "192.168.1.20",
            )
        )
        self.assertIsNone(
            discovery._description_path(
                "https://192.168.1.20/device.xml",
                "192.168.1.20",
            )
        )


class MDNSTests(unittest.TestCase):
    def test_build_query_has_questions(self) -> None:
        packet = discovery.build_mdns_query(("_http._tcp.local",))
        _, _, qdcount, _, _, _ = struct.unpack("!HHHHHH", packet[:12])
        self.assertEqual(qdcount, 1)
        self.assertIn(b"_http", packet)

    def test_parse_mdns_response_correlates_service_to_host(self) -> None:
        service = "_http._tcp.local"
        instance = "Cam One._http._tcp.local"
        hostname = "cam-one.local"

        ptr_data = discovery._encode_dns_name(instance)
        srv_data = struct.pack("!HHH", 0, 0, 8080) + discovery._encode_dns_name(hostname)
        txt_data = bytes([10]) + b"model=XC-1"
        a_data = bytes([192, 168, 1, 50])
        answers = (
            rr(service, 12, ptr_data)
            + rr(instance, 33, srv_data)
            + rr(instance, 16, txt_data)
            + rr(hostname, 1, a_data)
        )
        packet = struct.pack("!HHHHHH", 0, 0x8400, 0, 4, 0, 0) + answers

        records = discovery.parse_mdns_response(
            packet,
            ipaddress.IPv4Network("192.168.1.0/24"),
        )
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record.host, "192.168.1.50")
        self.assertEqual(record.service, service)
        self.assertEqual(record.name, "cam one")
        self.assertIn(("port", "8080"), record.metadata)


if __name__ == "__main__":
    unittest.main()
