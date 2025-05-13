# Wireless Network Scanner & Analyzer Detailed Documentations. 
 - Date: May 10, 2025 
 - Prepared by: Shankar Bhattarai, Anil Khatiwada, Manish Chaulagain.

## 🔍 Wi-Fi Scanner & Analyzer

A real-time wireless network inspection and visualization tool built with **Python**, **Flask**, **Scapy**, and a custom **JavaScript dashboard**. It allows users to scan nearby Wi-Fi networks, identify connected devices, and analyze security strength — all visualized through a stylish, interactive terminal interface in your browser.

> ⚠️ This project is for **educational and ethical** use only. Scanning unauthorized networks may be illegal in your region.

---

## 📚 Table of Contents

1. [Features](#features)  
2. [System Requirements](#system-requirements)  
3. [Installation](#installation)  
4. [Usage](#usage)  
5. [Project Structure](#project-structure)  
6. [Backend Function Descriptions](#backend-function-descriptions)  
7. [Frontend Component Descriptions](#frontend-component-descriptions)  
8. [API Endpoints](#api-endpoints)  
9. [Output Files](#output-files)  
10. [Future Enhancements](#future-enhancements)  
11. [Documentation](#documentation)  
12. [License](#license)

---

## 🚀 Features

- 📡 **Scan Wi-Fi networks** – SSID, BSSID, signal strength, channel, encryption
- 🧭 **Detect connected devices** – IP, MAC address, and vendor lookup
- 🔐 **Security rating** – WEP, WPA/WPA2/WPA3, Open network classification
- 📊 **Security summary report** – Generated per scan
- ⚡ **Real-time logs** – Live scanning feedback via Server-Sent Events (SSE)
- 🎛️ **Interactive terminal UI** – Stylish dashboard with log viewer and tabbed modal

---

## ✅ System Requirements

- **OS**: macOS or Linux (Ubuntu 24.04 tested)
- **Python**: 3.12+
- **Root Access**: Required for ARP scanning
- **Unsupported**: Windows
- **Hardware**: Wi-Fi adapter with monitor mode (avoid Docker/VM unless bridged)

---

## ⚙️ Installation

Clone the repository:

```bash
git clone https://github.com/your-username/wifi-scanner.git
cd wifi-scanner
```

Set up your environment:

```bash
make setup
```

---

## 🚦 Usage

To run the scanner:

```bash
sudo make run
```

Visit the frontend:

```
http://localhost:8080
```

To stop:

```bash
sudo make stop
```

To clean the environment:

```bash
sudo make clean
```

---

## 📁 Project Structure

```
wifi-scanner/
├── main.py                  # Flask backend logic
├── server.py                # Static file server
├── index.html               # Terminal-style UI
├── scan-results/            # Output JSON & summaries
├── Makefile                 # Automation commands
├── requirements.txt         # Python dependencies
└── images/                  # Screenshots/docs
```

---

## 🧠 Backend Function Descriptions (main.py)

| Function | Description |
|----------|-------------|
| run_command(cmd) | Executes shell commands (e.g., airport -s) and returns decoded output. |
| analyze_encryption(enc) | Converts encryption type to a security label (e.g., WPA2 → "Moderate"). |
| scan_wifi_networks() | Scans nearby SSIDs via airport, parses and streams results, saves to JSON. |
| get_connected_devices() | Performs ARP scan to find connected devices, logs MAC/IP/vendor. |
| lookup_vendor(mac) | Uses MAC Vendors API to resolve manufacturer from MAC address. |
| generate_security_summary() | Creates a formatted summary text file rating each network’s security. |

---

## 🖥️ Frontend Component Descriptions (index.html)

| Component | Description |
|----------|-------------|
| Terminal UI | Displays live scanning logs in real-time with color-coded lines. |
| Pulse Button (SVG) | Animated circular button showing scan status visually. |
| Modal Viewer | Fullscreen pop-up with tabs for Wi-Fi networks, devices, and security summary. |
| startScan() | Starts a scan, connects to /scan-stream, renders live logs. |
| classifyLine(line) | Parses log lines and assigns icons/styles (info, device, success, error). |
| fetchWifiNetworks() | Fetches and displays scanned SSIDs. |
| fetchConnectedDevices() | Fetches and displays ARP-discovered devices. |
| fetchSecuritySummary() | Fetches and displays plain-text security report. |

---

## 🔌 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| /scan-stream | GET | Starts Wi-Fi and ARP scan; returns SSE logs |
| /wifi-networks | GET | Returns scanned SSID data as JSON |
| /connected-devices | GET | Returns ARP-discovered devices as JSON |
| /security-summary | GET | Returns security summary in plain text |

---

## 🗃️ Output Files

| File | Description |
|------|-------------|
| wifi-networks.json | JSON array of nearby networks with signal, channel, encryption |
| devices.json | List of connected LAN devices (IP, MAC, Vendor) |
| security-summary.txt | Human-readable summary of encryption ratings |

---

## 🧭 Future Enhancements

- Cross-platform support (Windows/Linux)
- Device geolocation and heat mapping (Ocupado-style)
- Export reports as PDF/CSV
- Admin dashboard with historical analytics
- Voice-command integration
- Scheduled scanning with alert system

---

---

## 🛡️ License

This project is licensed under the MIT License.