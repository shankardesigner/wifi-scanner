import http.server
import os
import socketserver
import subprocess
import re
from scapy.all import ARP, Ether, srp
import requests
import json

# Paths
base_dir = "/home/ubuntu/Downloads/pentest-project"
output_dir = os.path.join(base_dir, "scan-results")
index_path = os.path.join(base_dir, "index.html")
PORT = 8080


def run_command(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode()
    except subprocess.CalledProcessError:
        return ""

# ------------------------------
# 1. Scan WiFi Networks
# ------------------------------

def scan_wifi_networks(interface='wlan0'):
    print("[*] Scanning for nearby Wi-Fi networks...")
    output = run_command(f"sudo iwlist {interface} scan")
    networks = []
    for cell in output.split("Cell "):
        ssid = re.search(r'ESSID:"(.+)"', cell)
        quality = re.search(r"Quality=(\d+)/(\d+)", cell)
        channel = re.search(r"Channel:(\d+)", cell)
        enc_type = "Open"
        if "WPA3" in cell:
            enc_type = "WPA3"
        elif "WPA2" in cell:
            enc_type = "WPA2"
        elif "WEP" in cell:
            enc_type = "WEP"

        if ssid:
            networks.append({
                "SSID": ssid.group(1),
                "Signal": f"{int(quality.group(1)) * 100 // int(quality.group(2))}%" if quality else "N/A",
                "Channel": channel.group(1) if channel else "N/A",
                "Encryption": enc_type
            })
    return networks

# ------------------------------
# 2. Get Connected Devices on LAN
# ------------------------------

def get_connected_devices(interface='wlan0'):
    print("[*] Scanning local network for connected devices...")
    ip_range = run_command(f"ip addr show {interface} | grep 'inet '").strip()
    match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', ip_range)
    if not match:
        return []

    cidr = f"{match.group(1)}/{match.group(2)}"
    arp_req = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=cidr)
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
    return devices

# ------------------------------
# 3. MAC Vendor Lookup
# ------------------------------

def lookup_vendor(mac):
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        return r.text if r.status_code == 200 else "Unknown"
    except:
        return "Unknown"

# ------------------------------
# 4. Security Analyzer
# ------------------------------

def analyze_network_security(networks):
    print("\n[*] Running Wi-Fi security analysis...\n")
    warnings = []
    networks_with_categories={"wep":[], "wpa":[], "open":[]}
    for net in networks:
        if net["Encryption"] == "WEP":
            networks_with_categories["wep"].append(net)
            warnings.append(f"[!] {net['SSID']} is using insecure WEP encryption.")
        elif net["Encryption"] == "Open":
            networks_with_categories["open"].append(net)
            warnings.append(f"[!] {net['SSID']} is an open network (no encryption).")
        else:
            networks_with_categories["wpa"].append(net)

            warnings.append(f"[+] {net['SSID']} uses {net['Encryption']}, which is more secure.")
        
        with open("./scan-results/network-analysis.json" , "w") as aa:
            aa.writelines(json.dumps(networks_with_categories))

    return warnings

# ------------------------------
# 5. Display Results
# ------------------------------

def print_networks(networks):
    print("\nNearby Wi-Fi Networks:")
    print("-" * 50)
    for net in networks:
        print(f"SSID: {net['SSID']}")
        print(f"Signal: {net['Signal']}")
        print(f"Channel: {net['Channel']}")
        print(f"Encryption: {net['Encryption']}")
        print("-" * 50)

def print_devices(devices):
    print("\nConnected Devices on LAN:")
    print("-" * 50)
    for dev in devices:
        print(f"IP Address: {dev['IP']}")
        print(f"MAC Address: {dev['MAC']}")
        print(f"Vendor: {dev['Vendor']}")
        print("-" * 50)

# ------------------------------
# Main
# ------------------------------

def main():
    # interface = input("Enter your Wi-Fi interface (default wlan0): ") or "wlan0"
    
    interface="wlp0s20f3"

    wifi_networks = scan_wifi_networks(interface)
    wifi_networks_file=open("./scan-results/wifi-networks.json", "w")
    wifi_networks_file.write(json.dumps(wifi_networks))

    print_networks(wifi_networks)

    devices = get_connected_devices(interface)
    print_devices(devices)

    devices_file=open("./scan-results/devices.json", "w")
    devices_file.writelines(json.dumps(devices))

    warnings = analyze_network_security(wifi_networks)

    print("\nSecurity Analysis Summary:")

    for w in warnings:
        print(w)

def start_server():
    os.chdir(base_dir)
    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", PORT), handler) as httpd:
        print(f"Serving at http://localhost:{PORT}")
        httpd.serve_forever()

  
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Please run this script as root (sudo).")
    else:
        main()
        start_server()
