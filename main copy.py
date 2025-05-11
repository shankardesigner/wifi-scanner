import http.server
import os
import socketserver
import subprocess
import re
from scapy.all import ARP, Ether, srp
import requests
import json
import netifaces

# Paths
base_dir = os.getcwd()
output_dir = os.path.join(base_dir, "scan-results")
os.makedirs(output_dir, exist_ok=True)  # Ensure directory exists
PORT = 8080

def run_command(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.PIPE).decode()
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {cmd}\nError: {e.stderr.decode()}")
        return ""

def scan_wifi_networks(interface='en0'):
    print("[*] Scanning for nearby Wi-Fi networks...")
    # Use macOS specific command
    cmd = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s"
    output = run_command(cmd)
    
    networks = []
    for line in output.split('\n')[1:]:  # Skip header line
        if not line.strip():
            continue
            
        # Parse macOS airport output
        parts = re.split(r'\s{2,}', line.strip())
        if len(parts) >= 4:
            networks.append({
                "SSID": parts[0],
                "BSSID": parts[1],
                "Signal": parts[2],
                "Channel": parts[3],
                "Encryption": parts[4] if len(parts) > 4 else "Open"
            })
    return networks

def get_connected_devices(interface='en0'):
    print("[*] Scanning local network for connected devices...")
    try:
        # Get network info using netifaces
        addrs = netifaces.ifaddresses(interface)
        ip_info = addrs[netifaces.AF_INET][0]
        ip = ip_info['addr']
        netmask = ip_info['netmask']
        
        # Calculate network address
        network = '.'.join([str(int(ip.split('.')[i]) & int(netmask.split('.')[i])) 
                      for i in range(4)])
        cidr = sum(bin(int(x)).count('1') for x in netmask.split('.'))
        ip_range = f"{network}/{cidr}"
        
        # Perform ARP scan
        arp_req = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range)
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
    except Exception as e:
        print(f"Error scanning devices: {e}")
        return []

def lookup_vendor(mac):
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        return r.text if r.status_code == 200 else "Unknown"
    except Exception as e:
        print(f"Vendor lookup failed: {e}")
        return "Unknown"

def analyze_network_security(networks):
    print("\n[*] Running Wi-Fi security analysis...\n")
    warnings = []
    networks_with_categories = {"wep": [], "wpa": [], "open": []}
    
    for net in networks:
        enc = net["Encryption"]
        if "WEP" in enc:
            networks_with_categories["wep"].append(net)
            warnings.append(f"[!] {net['SSID']} is using insecure WEP encryption.")
        elif "Open" in enc:
            networks_with_categories["open"].append(net)
            warnings.append(f"[!] {net['SSID']} is an open network (no encryption).")
        else:
            networks_with_categories["wpa"].append(net)
            warnings.append(f"[+] {net['SSID']} uses {enc}, which is more secure.")
    
    with open(os.path.join(output_dir, "network-analysis.json"), "w") as f:
        json.dump(networks_with_categories, f, indent=2)
    
    return warnings

def print_networks(networks):
    print("\nNearby Wi-Fi Networks:")
    print("-" * 70)
    print(f"{'SSID':<30}{'Signal':<15}{'Channel':<10}{'Encryption':<15}")
    print("-" * 70)
    for net in networks:
        print(f"{net['SSID'][:28]:<30}{net['Signal']:<15}{net['Channel']:<10}{net['Encryption']:<15}")

def print_devices(devices):
    print("\nConnected Devices on LAN:")
    print("-" * 70)
    print(f"{'IP':<15}{'MAC':<20}{'Vendor':<35}")
    print("-" * 70)
    for dev in devices:
        print(f"{dev['IP']:<15}{dev['MAC']:<20}{dev['Vendor'][:30]:<35}")

def main():
    interface = "en0"  # Default for macOS
    
    # Scan networks
    wifi_networks = scan_wifi_networks(interface)
    with open(os.path.join(output_dir, "wifi-networks.json"), "w") as f:
        json.dump(wifi_networks, f, indent=2)
    
    print_networks(wifi_networks)

    # Scan devices
    devices = get_connected_devices(interface)
    with open(os.path.join(output_dir, "devices.json"), "w") as f:
        json.dump(devices, f, indent=2)
    
    print_devices(devices)

    # Analyze security
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
        # Uncomment to start web server after scanning
        # start_server()