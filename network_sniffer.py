import sys
import json
import os
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTPRequest
from colorama import init, Fore
from datetime import datetime

# Initialize colorama
init()
r = Fore.RED
g = Fore.GREEN
bu = Fore.BLUE
y = Fore.YELLOW
rst = Fore.RESET

# JSON file path
JSON_LOG_FILE = "api/traffic/sniffed_packets.json"

# Initialize the JSON file with an empty "packets" array and counts for TCP and UDP
def initialize_json_file():
    try:
        os.makedirs(os.path.dirname(JSON_LOG_FILE), exist_ok=True)

        # Check if file exists and contains valid JSON
        with open(JSON_LOG_FILE, "r") as json_file:
            data = json.load(json_file)
            if "packets" not in data:  # Ensure the key "packets" exists
                raise ValueError("Invalid JSON structure")
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        # Create or reset the JSON file with an empty "packets" array and total counts
        with open(JSON_LOG_FILE, "w") as json_file:
            json.dump({"packets": [], "alerts": [], "total_counts": {"TCP": 0, "UDP": 0}}, json_file, indent=4)

# Append data to the "packets" array in the JSON file
def write_to_json(data):
    try:
        with open(JSON_LOG_FILE, "r") as json_file:
            logs = json.load(json_file)

        logs["packets"].append(data)  # Append to the "packets" array
        logs["total_counts"][data["protocol"]] += 1  # Increment the protocol count (TCP or UDP)

        with open(JSON_LOG_FILE, "w") as json_file:
            json.dump(logs, json_file, indent=4)
    except Exception as e:
        print(f"{r}[!] Error writing to JSON file: {str(e)}{rst}")

# Function to trigger alerts based on specific conditions (e.g., large packet size)
def trigger_alert(packet_data):
    alert_message = None
    if packet_data["size"] > 1000:  # Example: large packet alert
        alert_message = f"Large {packet_data['protocol']} packet detected. Possible attack."

    if alert_message:
        alert_data = {
            "time": packet_data["timestamp"],
            "protocol": packet_data["protocol"],
            "size": packet_data["size"],
            "message": alert_message
        }
        try:
            with open(JSON_LOG_FILE, "r") as json_file:
                logs = json.load(json_file)
            logs["alerts"].append(alert_data)
            with open(JSON_LOG_FILE, "w") as json_file:
                json.dump(logs, json_file, indent=4)
        except Exception as e:
            print(f"{r}[!] Error writing alert to JSON file: {str(e)}{rst}")

# Sniff packets on the specified interface
def sniff_packets(iface):
    try:
        print(f"{g}[*] Starting packet sniffing on {iface if iface else 'all interfaces'}...{rst}")
        sniff(prn=process_packet, iface=iface, store=False, filter="tcp or udp")
    except PermissionError:
        print(f"{r}[!] Permission denied. Run as administrator/root.{rst}")
    except KeyboardInterrupt:
        print(f"{y}[!] Sniffing stopped by user.{rst}")
        sys.exit(0)
    except Exception as e:
        print(f"{r}[!] Error: {str(e)}{rst}")

# Process each captured packet
def process_packet(packet):
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

        # Trigger alerts for any suspicious packets
        trigger_alert(packet_data)

    except Exception as e:
        print(f"{r}[!] Error processing packet: {str(e)}{rst}")

# Main function to start the packet sniffer
def main():
    iface = sys.argv[1] if len(sys.argv) > 1 else None
    sniff_packets(iface)

if __name__ == "__main__":
    initialize_json_file()
    main()