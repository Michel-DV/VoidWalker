# 🌌 VoidWalker - Network Auditor

**VoidWalker** is a high-speed, multi-threaded network auditing tool written in Python. It is specifically designed to identify insecure IoT devices and detect potential botnet backdoors (such as Mirai, Gafgyt, or Kimwolf) within a local network.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.x-green.svg)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey)

---
## 📸 Preview
![VoidWalker in action](screenshot_demo.png)

*Example of VoidWalker detecting a simulated Botnet Risk (Red) and a Configuration Risk (Yellow).*

## 🛡️ Overview
In an era of vulnerable IoT hardware, **VoidWalker** provides an efficient way to audit your network. It scans for specific ports often targeted by malware or left exposed by poor configurations, attempting to perform "Banner Grabbing" to verify the service identity.

---

## ✨ Key Features
* **Dual-Threat Classification:** Automatically categorizes findings into **Botnet Risks** (active threats) and **Configuration Risks** (potential vulnerabilities).
* **Advanced Banner Grabbing:** Attempts to retrieve service signatures to confirm the nature of the open port.
* **High Performance:** Powered by `ThreadPoolExecutor` to handle up to 100 simultaneous host audits.
* **Zero Dependencies:** Built entirely with Python standard libraries such as `socket`, `threading`, and `ipaddress`.
* **Smart Detection:** Automatically detects your local IP and suggests the appropriate `/24` subnet for scanning.

---

## 🔍 Targeted Ports

VoidWalker monitors the following critical entry points:

| Category | Ports | Description |
| :--- | :--- | :--- |
| **Botnet Risk** | 23, 2323, 5555, 37215, 52869, 4321 | Known targets for Mirai, Gafgyt, and Android botnets. |
| **Config Risk** | 21, 445, 1900, 5431, 8080 | Insecure protocols (FTP, SMB) or exposed Admin UIs. |

---

## 🚀 Getting Started

### Prerequisites
* Python 3.x installed.

### Installation
1. **Clone the repository:**
   ```bash
   git clone [https://github.com/Michel-DV/VoidWalker.git](https://github.com/Michel-DV/VoidWalker.git)
   cd VoidWalker

## 🚀 Usage

Run the script directly from your terminal:

```bash
python VoidWalker.py

```

## 🎯 Target Selection
Upon startup, the tool will ask for a target network range.

Quick Scan: Press Enter to scan your local network automatically
(e.g., 192.168.1.0/24)

## ⚙️ How It Works
Discovery
The tool identifies your local IP address to determine the default scan scope.

## Audit
Iterates through the IP range, performing TCP connection attempts on risky ports.

## Interaction
If a port is open, it attempts to read the first 1024 bytes (banner) to identify the service.

## Reporting
Results are displayed in real time with color-coded severity levels:

🔴 Red → Botnet Risks

🟡 Yellow → Configuration Risks

## ⚠️ Disclaimer
VoidWalker is intended exclusively for educational purposes and authorized security auditing.
Scanning networks without explicit permission is illegal.

The author assumes no responsibility for misuse of this tool.

## 📜 License
Distributed under the MIT License.
See the LICENSE file for more information.

