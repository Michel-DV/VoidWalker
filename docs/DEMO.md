# VoidWalker demo — synthetic IoT lab

This walkthrough uses **synthetic private-network data** to show what a normal VoidWalker run is designed to surface. It is intentionally non-exploitative: the goal is to identify devices, risky exposure, vulnerability candidates, and evidence that may justify a compromise investigation.

## Command

```bash
python VoidWalker.py --network 192.168.50.0/24
```

## Example output

```text
VoidWalker v2.1.0 - IoT discovery, exposure and compromise triage
Scope: 192.168.50.0/24
Hosts: 254 | TCP ports: 17 | Open-service findings: 6 | Discovery records: 5 | Indicators: 3
------------------------------------------------------------------------------------
DEVICE INTELLIGENCE
  192.168.50.22  -> Hikvision / DS-2CD / camera
      names: office-cam
      discovery: mdns, ssdp
      services: HTTP/vendor management, RTSP
  192.168.50.34  -> Espressif / lab-iot-01 / android/embedded device
      names: lab-iot-01
      discovery: mdns
      services: ADB / debug service, Telnet
------------------------------------------------------------------------------------
TCP EXPOSURE FINDINGS
  [MEDIUM  ] 192.168.50.22:554   RTSP  (media-streaming)
             RTSP commonly identifies cameras/NVRs; verify authentication, firmware, and network exposure.
  [HIGH    ] 192.168.50.34:23    Telnet  (legacy-cleartext)
             Telnet is a high-risk management surface frequently targeted on embedded devices.
  [HIGH    ] 192.168.50.34:5555  ADB / debug service  (debug-interface)
             Android Debug Bridge or vendor debug services should not normally be reachable by peers.
------------------------------------------------------------------------------------
VULNERABILITY / COMPROMISE TRIAGE
  [CRITICAL] 192.168.50.34 compromise-indicator / confidence=medium
             Mirai family string observed in device/service evidence
             A malware-family name appeared in a service banner or discovery record.
             evidence: Mirai
  [HIGH    ] 192.168.50.34 compromise-suspicion / confidence=low
             Multiple botnet-targeted management surfaces are reachable
             Several services commonly targeted on embedded devices are reachable at the same host.
             evidence: tcp/23, tcp/5555
------------------------------------------------------------------------------------
Triage output is evidence-based but not proof: vulnerability candidates require model/firmware
confirmation, and compromise indicators require follow-up inspection.
```

## How to read the result

The important part is the **correlation**.

`192.168.50.22` looks like a camera and exposes services worth reviewing, but there is no built-in compromise signal in the example.

`192.168.50.34` deserves faster investigation because several independent observations line up on the same host:

- discovery identifies an embedded/IoT-style device;
- Telnet and ADB/debug are reachable;
- the host exposes more than one service commonly targeted by IoT botnets;
- collected evidence contains a malware-family string.

VoidWalker therefore raises an investigation lead with a confidence level instead of declaring the host infected.

## What to do next

A real suspicious result should be followed by defensive validation such as:

- confirm device make, model, and firmware;
- review DHCP/DNS history and outbound destinations;
- capture and inspect network traffic;
- check whether the exposed service is expected;
- isolate the device if the evidence and business context justify it;
- use vendor-specific firmware or forensic procedures where available.

## Vulnerability candidate example

VoidWalker can also flag explicit software fingerprints. For example, evidence containing `RomPager/4.34` can produce a high-confidence **vulnerability candidate** for CVE-2014-9222. The tool still requires the operator to confirm the actual device model and firmware before calling the device vulnerable.

For the exact matching and confidence logic, see [`DETECTION_MODEL.md`](DETECTION_MODEL.md).
