# ===================headers========================
import sys
import json
import os
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.http import HTTPRequest, TCP
from colorama import init, Fore
from datetime import datetime

# =================color=declaration================

init()
r = Fore.RED  # RED
g = Fore.GREEN  # GREEN
bu = Fore.BLUE  # BLUE
y = Fore.YELLOW  # YELLOW
c = Fore.CYAN  # CYAN
rst = Fore.RESET  # RESET color

# ==================================================
JSON_LOG_FILE = "api/traffic/sniffed_packets.json"


# Initialize the JSON file with an empty "packets" array
def initialize_json_file():
    try:
        os.makedirs(os.path.dirname(JSON_LOG_FILE), exist_ok=True)

        # Check if file exists and contains valid JSON
        with open(JSON_LOG_FILE, "r") as json_file:
            data = json.load(json_file)
            if "packets" not in data:  # Ensure the key "packets" exists
                raise ValueError("Invalid JSON structure")
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        # Create or reset the JSON file with an empty "packets" array
        with open(JSON_LOG_FILE, "w") as json_file:
            json.dump({"packets": []}, json_file, indent=4)


# Append data to the "packets" array in the JSON file
def write_to_json(data):
    try:
        with open(JSON_LOG_FILE, "r") as json_file:
            logs = json.load(json_file)

        logs["packets"].append(data)  # Append to the "packets" array

        with open(JSON_LOG_FILE, "w") as json_file:
            json.dump(logs, json_file, indent=4)
    except Exception as e:
        print(f"{r}[!] Error writing to JSON file: {str(e)}{rst}")


# Sniff packets on the specified interface
def sniff_packets(iface):
    try:
        print(f"{g}[*] Starting packet sniffing on {iface if iface else 'all interfaces'}...{rst}")
        sniff(prn=prc_packets, iface=iface, store=False, filter="tcp or udp")
    except PermissionError:
        print(f"{r}[!] Permission denied. Run as administrator/root.{rst}")
    except KeyboardInterrupt:
        print(f"{y}[!] Sniffing stopped by user.{rst}")
        sys.exit(0)
    except Exception as e:
        print(f"{r}[!] Error: {str(e)}{rst}")


# Process each captured packet
def prc_packets(packet):
    try:
        packet_data = {
            "timestamp": datetime.now().isoformat(),
            "size": len(packet),  # Packet size in bytes
        }

        # Check and log IP layer details
        if packet.haslayer(IP):
            packet_data["src_ip"] = packet[IP].src
            packet_data["dst_ip"] = packet[IP].dst
        else:
            packet_data["src_ip"] = "Unknown"
            packet_data["dst_ip"] = "Unknown"

        # Check and log TCP/UDP layer details
        if packet.haslayer(TCP):
            packet_data["protocol"] = "TCP"
            packet_data["src_port"] = packet[TCP].sport
            packet_data["dst_port"] = packet[TCP].dport
            print(
                f"{bu}[+] {packet_data['src_ip']} is using port {packet_data['src_port']} to connect to {packet_data['dst_ip']} at port {packet_data['dst_port']} (TCP){rst}")
        elif packet.haslayer(UDP):
            packet_data["protocol"] = "UDP"
            packet_data["src_port"] = packet[UDP].sport
            packet_data["dst_port"] = packet[UDP].dport
            print(
                f"{bu}[+] {packet_data['src_ip']} is using port {packet_data['src_port']} to connect to {packet_data['dst_ip']} at port {packet_data['dst_port']} (UDP){rst}")
        else:
            packet_data["protocol"] = "Other"

        # Check and log HTTP request details
        if packet.haslayer(HTTPRequest):
            url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
            method = packet[HTTPRequest].Method.decode()
            packet_data["http_request"] = {"url": url, "method": method}
            print(f"{g}[+] {packet_data['src_ip']} is making an HTTP request to {url} with method {method}{rst}")

        # Check and log raw payload data if available
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load.decode(errors="ignore")
            packet_data["raw_data"] = raw_data
            print(f"{r}[+] Raw Data: {raw_data}{rst}")

        # Save the packet data to the JSON file
        write_to_json(packet_data)

    except Exception as e:
        print(f"{r}[!] Error processing packet: {str(e)}{rst}")


# Main function to start the packet sniffer
def main():
    iface = sys.argv[1] if len(sys.argv) > 1 else None
    sniff_packets(iface)


if __name__ == "__main__":
    initialize_json_file()
    main()