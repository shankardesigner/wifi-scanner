# 🔍 WiFi Scanning with Python

This repository contains a Python-based system to scan nearby WiFi networks, detect connected devices, and analyze WiFi security using a live log stream and interactive browser dashboard.

---

## 📚 Table of Contents

1. [System Requirements](#system-requirements)  
2. [Setup and Installation](#setup-and-installation)  
3. [Using the Application](#using-the-application)  
4. [Project Structure](#project-structure)  
5. [Makefile Commands](#makefile-commands)  

---

## ✅ System Requirements

- **Operating System:** Linux or macOS  
- **Python Version:** 3.12+  
- **Root Access:** Required for ARP scanning  
- **Tested On:** Ubuntu 24.04 (Live USB boot)  

> ⚠️ Not supported on Windows. Avoid running in virtualized environments like Docker or VirtualBox unless properly bridged to host WiFi hardware.

---

## ⚙️ Setup and Installation

Clone the repository:

```bash
git clone git@github.com:shankardesigner/wifi-scanner.git
cd wifi-scanner
```

Install and configure everything with one command:

```bash
make setup
```

This will:
- Create a virtual environment (`venv`)
- Install required Python dependencies

---

## 🚀 Using the Application

Run the application with:

```bash
sudo make run
```

This will:
- Stop any previously running servers
- Start `main.py` (Flask API on port 5000)
- Start `server.py` (static frontend on port 8080)
- Open your default browser at `http://localhost:8080`

Stop all running processes:

```bash
sudo make stop
```

Clean up the environment:

```bash
sudo make clean
```

---

## 📁 Project Structure

```
wifi-scanner/
├── main.py                  # Flask backend (scan APIs)
├── server.py                # Static file server (frontend)
├── requirements.txt         # Python dependencies
├── Makefile                 # Automation commands
├── scan-results/            # Output JSON and summaries
├── images/                  # Screenshots for README
└── index.html               # Frontend dashboard
```

---

## 🛠️ Makefile Commands

```bash
sudo make setup     # Set up virtualenv + install packages
sudo make run       # Start backend + frontend servers
sudo make stop      # Kill running Python processes
sudo make clean     # Full cleanup (venv, output, cache)
```

---

## 🏁 Final Note

This tool is for **educational and ethical security research only**. Do not scan networks without permission.

---
