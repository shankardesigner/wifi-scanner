from flask import Flask, Response, stream_with_context, jsonify
import subprocess
import re
from scapy.all import ARP, Ether, srp
import requests
import json
import os
import netifaces
import time

app = Flask(__name__)
from flask_cors import CORS
CORS(app)

base_dir = os.getcwd()
output_dir = os.path.join(base_dir, "scan-results")
os.makedirs(output_dir, exist_ok=True)

def run_command(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.PIPE).decode()
    except subprocess.CalledProcessError as e:
        return f"Command failed: {cmd}\nError: {e.stderr.decode()}"

def analyze_encryption(enc):
    enc = enc.upper()
    if "WEP" in enc:
        return "Insecure (WEP)"
    elif "WPA3" in enc:
        return "Strong (WPA3)"
    elif "WPA2" in enc:
        return "Moderate (WPA2)"
    elif "WPA" in enc:
        return "Weak (WPA)"
    elif "OPEN" in enc or enc == "OPEN":
        return "Unsecured (Open)"
    else:
        return "Unknown"

def scan_wifi_networks(interface='en0'):
    yield "data: [*] Scanning for nearby Wi-Fi networks...\n\n".encode()
    cmd = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s"
    output = run_command(cmd)

    networks = []
    for line in output.split('\n')[1:]:
        if not line.strip():
            continue
        parts = re.split(r'\s{2,}', line.strip())
        if len(parts) >= 4:
            encryption = parts[4] if len(parts) > 4 else "Open"
            net = {
                "SSID": parts[0],
                "BSSID": parts[1],
                "Signal": parts[2],
                "Channel": parts[3],
                "Encryption": encryption,
                "SecurityRating": analyze_encryption(encryption)
            }
            networks.append(net)
            yield f"data: $ Found: {net['SSID']} [{net['Signal']} dBm] - {net['SecurityRating']}\n\n".encode()

    with open(os.path.join(output_dir, "wifi-networks.json"), "w") as f:
        json.dump(networks, f, indent=2)

    yield f"data: $ Wi-Fi scan complete ({len(networks)} networks found)\n\n".encode()
    return networks

def get_connected_devices(interface='en0'):
    yield "data: [*] Scanning local network for connected devices...\n\n".encode()
    try:
        addrs = netifaces.ifaddresses(interface)
        ip_info = addrs[netifaces.AF_INET][0]
        ip = ip_info['addr']
        netmask = ip_info['netmask']
        network = '.'.join([str(int(ip.split('.')[i]) & int(netmask.split('.')[i])) for i in range(4)])
        cidr = sum(bin(int(x)).count('1') for x in netmask.split('.'))
        ip_range = f"{network}/{cidr}"

        arp_req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
        ans, _ = srp(arp_req, timeout=2, verbose=0, iface=interface)

        devices = []
        for _, rcv in ans:
            mac = rcv[Ether].src
            ip = rcv[ARP].psrc
            vendor = lookup_vendor(mac)
            devices.append({
                "IP": ip,
                "MAC": mac,
                "Vendor": vendor
            })
            yield f"data: $ Device: {ip} - {mac} ({vendor})\n\n".encode()

        with open(os.path.join(output_dir, "devices.json"), "w") as f:
            json.dump(devices, f, indent=2)

        yield f"data: $ Device scan complete ({len(devices)} devices found)\n\n".encode()
        return devices
    except Exception as e:
        yield f"data: $ Error: {e}\n\n".encode()
        return []

def lookup_vendor(mac):
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        return r.text if r.status_code == 200 else "Unknown"
    except:
        return "Unknown"

def generate_security_summary(networks):
    warnings = []
    for net in networks:
        rating = net.get("SecurityRating", "Unknown")
        ssid = net.get("SSID", "Unknown")[:20]
        bssid = net.get("BSSID", "??:??:??:??:??:??")
        signal = net.get("Signal", "-99").strip()

        # Padding and formatting for clean alignment
        line = f"[!] {ssid.ljust(20)}  {bssid.ljust(20)}  {signal.rjust(4)}  - {rating}"
        warnings.append(line)

    with open(os.path.join(output_dir, "security-summary.txt"), "w") as f:
        f.write("\n".join(warnings))

    return warnings



@app.route("/scan-stream")
def scan_stream():
    def generate():
        interface = "en0"
        start = time.time()

        # --- Step 1: Scan Wi-Fi Networks ---
        yield b"data: [*] Scanning for nearby Wi-Fi networks...\n\n"
        cmd = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s"
        output = run_command(cmd)

        networks = []
        for line in output.split('\n')[1:]:
            if not line.strip():
                continue
            parts = re.split(r'\s{2,}', line.strip())
            if len(parts) >= 4:
                encryption = parts[4] if len(parts) > 4 else "Open"
                net = {
                    "SSID": parts[0],
                    "BSSID": parts[1],
                    "Signal": parts[2],
                    "Channel": parts[3],
                    "Encryption": encryption,
                    "SecurityRating": analyze_encryption(encryption)
                }
                networks.append(net)
                msg = f"$ Found: {net['SSID']} [{net['Signal']} dBm] - {net['SecurityRating']}\n\n"
                yield f"data: {msg}".encode()
                time.sleep(0.3)

        with open(os.path.join(output_dir, "wifi-networks.json"), "w") as f:
            json.dump(networks, f, indent=2)

        yield f"data: $ Wi-Fi scan complete ({len(networks)} networks found)\n\n".encode()
        time.sleep(0.5)

        # --- Step 2: Scan Connected Devices ---
        yield b"data: [*] Scanning local network for connected devices...\n\n"
        try:
            addrs = netifaces.ifaddresses(interface)
            ip_info = addrs[netifaces.AF_INET][0]
            ip = ip_info['addr']
            netmask = ip_info['netmask']
            network = '.'.join([str(int(ip.split('.')[i]) & int(netmask.split('.')[i])) for i in range(4)])
            cidr = sum(bin(int(x)).count('1') for x in netmask.split('.'))
            ip_range = f"{network}/{cidr}"

            arp_req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
            ans, _ = srp(arp_req, timeout=2, verbose=0, iface=interface)

            devices = []
            for _, rcv in ans:
                mac = rcv[Ether].src
                ip = rcv[ARP].psrc
                vendor = lookup_vendor(mac)
                devices.append({
                    "IP": ip,
                    "MAC": mac,
                    "Vendor": vendor
                })
                msg = f"$ Device: {ip} - {mac} ({vendor})\n\n"
                yield f"data: {msg}".encode()
                time.sleep(0.3)

            with open(os.path.join(output_dir, "devices.json"), "w") as f:
                json.dump(devices, f, indent=2)

            yield f"data: $ Device scan complete ({len(devices)} devices found)\n\n".encode()
        except Exception as e:
            yield f"data: $ Error: {str(e)}\n\n".encode()

        # --- Step 3: Security Summary ---
        security_notes = generate_security_summary(networks)
        yield b"data: $ Security Analysis Summary:\n\n"
        for note in security_notes:
            yield f"data: $ {note}\n\n".encode()
            time.sleep(0.2)

        # --- Step 4: Final Message ---
        duration = time.time() - start
        yield f"data: $ Scan completed in {duration:.2f} seconds\n\n".encode()
        yield b"data: $ --- End of Scan ---\n\n"
        yield b"data: $ END_OF_STREAM\n\n"

    return Response(stream_with_context(generate()), mimetype='text/event-stream', direct_passthrough=True)


# --- New API Endpoints ---

@app.route("/wifi-networks", methods=["GET"])
def get_wifi_networks():
    try:
        with open(os.path.join(output_dir, "wifi-networks.json")) as f:
            return jsonify(json.load(f))
    except FileNotFoundError:
        return jsonify({"error": "Wi-Fi networks not scanned yet."}), 404

@app.route("/connected-devices", methods=["GET"])
def get_devices():
    try:
        with open(os.path.join(output_dir, "devices.json")) as f:
            return jsonify(json.load(f))
    except FileNotFoundError:
        return jsonify({"error": "Devices not scanned yet."}), 404

@app.route("/security-summary", methods=["GET"])
def get_security_summary():
    try:
        with open(os.path.join(output_dir, "security-summary.txt")) as f:
            return Response(f.read(), mimetype='text/plain')
    except FileNotFoundError:
        return Response("Security summary not available. Run /scan-stream first.", status=404)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Run this script with sudo: root privileges are required for ARP scans.")
    else:
        app.run(port=5000, debug=False)
