import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
from scapy.all import sniff, Packet, conf
import json
import time
import winsound
from collections import defaultdict
from datetime import datetime

MAX_TRIES = 50
PACKET_THRESHOLD = 10
conf.l3socket = conf.L3socket


class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        self.tries = 0
        self.packet_count = 0
        self.packets = []
        self.src_ip_packet_count = defaultdict(int)
        self.dst_ip_packet_count = defaultdict(int)
        self.protocol_map = {
            1: "ICMP",
            2: "IGMP",
            6: "TCP",
            17: "UDP",
            41: "IPv6",
            43: "IPv6 Route",
            44: "IPv6 Frag",
            50: "ESP (Encapsulating Security Payload)",
            51: "AH (Authentication Header)",
            58: "ICMPv6",
            59: "IPv6 No Next Header",
            60: "IPv6 Destination Options",
            89: "OSPF (Open Shortest Path First)",
            112: "VRRP (Virtual Router Redundancy Protocol)",
            115: "L2TP (Layer 2 Tunneling Protocol)",
            130: "SFTP (Secure File Transfer Protocol)",
            132: "FC (Fibre Channel)",
            137: "NetBIOS Name Service",
            138: "NetBIOS Datagram",
            139: "NetBIOS Session",
            151: "PPP (Point-to-Point Protocol)",
            162: "SNMP Trap",
            163: "SNMP",
            164: "CMIP (Common Management Information Protocol)",
            166: "HTTP (Hypertext Transfer Protocol)",
            170: "NTP (Network Time Protocol)",
            183: "X.25 (Packet Mode)",
            184: "X.25 L2",
            186: "MPLS (Multiprotocol Label Switching)",
            204: "IPX",
            253: "DCCP (Datagram Congestion Control Protocol)",
            254: "SCTP (Stream Control Transmission Protocol)",
            255: "Reserved",
        }

        # Input frame
        self.input_frame = tk.Frame(self.root)
        self.input_frame.pack(pady=10)

        # Protocol
        tk.Label(self.input_frame, text="Protocol:").grid(
            row=0, column=0, padx=5, pady=5
        )
        self.protocol_entry = tk.Entry(self.input_frame, width=20)
        self.protocol_entry.grid(row=0, column=1, padx=5, pady=5)

        # Size
        tk.Label(self.input_frame, text="Min Size (bytes):").grid(
            row=1, column=0, padx=5, pady=5
        )
        self.size_entry = tk.Entry(self.input_frame, width=20)
        self.size_entry.grid(row=1, column=1, padx=5, pady=5)

        # Source IP
        tk.Label(self.input_frame, text="Source IP:").grid(
            row=2, column=0, padx=5, pady=5
        )
        self.src_entry = tk.Entry(self.input_frame, width=20)
        self.src_entry.grid(row=2, column=1, padx=5, pady=5)

        # Destination IP
        tk.Label(self.input_frame, text="Destination IP:").grid(
            row=3, column=0, padx=5, pady=5
        )
        self.dst_entry = tk.Entry(self.input_frame, width=20)
        self.dst_entry.grid(row=3, column=1, padx=5, pady=5)

        # Packet Count
        tk.Label(self.input_frame, text="Packet Count:").grid(
            row=4, column=0, padx=5, pady=5
        )
        self.count_entry = tk.Entry(self.input_frame, width=20)
        self.count_entry.grid(row=4, column=1, padx=5, pady=5)

        # Start Button
        self.start_button = tk.Button(
            self.input_frame, text="Start Sniffing", command=self.start_sniffing
        )
        self.start_button.grid(row=5, column=0, columnspan=2, pady=10)

        # Output frame
        self.output_frame = tk.Frame(self.root)
        self.output_frame.pack(pady=10)

        # Table for displaying packets
        self.tree = ttk.Treeview(
            self.output_frame,
            columns=("Time", "Protocol", "Source", "Destination", "Size", "TTL"),
            show="headings",
        )
        self.tree.heading("Time", text="Time")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Source", text="Source")
        self.tree.heading("Destination", text="Destination")
        self.tree.heading("Size", text="Size (bytes)")
        self.tree.heading("TTL", text="TTL")
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Text box for alerts
        self.alert_text = scrolledtext.ScrolledText(
            self.output_frame, width=50, height=10, wrap=tk.WORD
        )
        self.alert_text.pack(pady=10)

    def beep(self):
        winsound.Beep(500, 500)

    def start_sniffing(self):
        # Clear output
        self.packet_count = 0
        self.packets = []
        self.src_ip_packet_count.clear()
        self.dst_ip_packet_count.clear()
        self.alert_text.delete(1.0, tk.END)
        for item in self.tree.get_children():
            self.tree.delete(item)

        filters = self.get_filters()
        self.tries = 0
        threading.Thread(target=self.sniff_packets, args=(filters,)).start()

    def get_filters(self):
        filters = {
            "protocol": (
                self.protocol_entry.get().strip()
                if self.protocol_entry.get().strip()
                else None
            ),
            "size": (
                int(self.size_entry.get().strip())
                if self.size_entry.get().strip()
                else None
            ),
            "src": self.src_entry.get().strip() or None,
            "dst": self.dst_entry.get().strip() or None,
            "count": (
                int(self.count_entry.get().strip())
                if self.count_entry.get().strip()
                else 10
            ),
        }
        return filters

    def sniff_packets(self, filters):
        while self.tries < MAX_TRIES and self.packet_count < filters.get("count"):
            try:
                sniff(
                    prn=lambda packet: self.process_packet(packet, filters),
                    store=0,
                    count=1,
                )
            except Exception as e:
                self.display_error(f"Error: {e}")
        if self.packet_count < filters["count"]:
            self.display_error(
                f"Failed to capture {filters.get('count')} packets. Exceeded max tries."
            )
        else:
            for packet_data in self.packets:
                self.display_packet(packet_data)

    def add_to_ip_packet_count(self, packet: Packet):
        global PACKET_THRESHOLD
        if packet.haslayer("IP"):
            src_ip = packet["IP"].src
            dst_ip = packet["IP"].dst
            self.src_ip_packet_count[src_ip] += 1
            self.dst_ip_packet_count[dst_ip] += 1

            if self.src_ip_packet_count[src_ip] > PACKET_THRESHOLD:
                self.beep()
                self.alert_text.insert(
                    tk.END, f"ALERT: Source IP {src_ip} sending too many packets!\n"
                )
                self.alert_text.tag_add("error", "1.0", tk.END)
                self.alert_text.tag_config("error", foreground="red")
                self.alert_text.yview(tk.END)
            elif self.dst_ip_packet_count[dst_ip] > PACKET_THRESHOLD:
                self.beep()
                self.alert_text.insert(
                    tk.END,
                    f"ALERT: Destination IP {dst_ip} receiving too many packets!\n",
                )
                self.alert_text.tag_add("error", "1.0", tk.END)
                self.alert_text.tag_config("error", foreground="red")
                self.alert_text.yview(tk.END)

    def process_packet(self, packet: Packet, filters: dict):
        self.add_to_ip_packet_count(packet)
        protocol = (
            self.resolve_protocol(packet["IP"].proto)
            if packet.haslayer("IP")
            else "Unknown"
        )
        if filters.get("protocol") != None and not packet.haslayer(
            filters["protocol"].upper()
        ):
            self.tries += 1
            return

        if filters["size"] != None and len(packet) < filters["size"]:
            self.tries += 1
            return

        if (
            filters["src"] != None
            and packet.haslayer("IP")
            and packet["IP"].src != filters["src"]
        ):
            self.tries += 1
            return

        if (
            filters["dst"] != None
            and packet.haslayer("IP")
            and packet["IP"].dst != filters["dst"]
        ):
            self.tries += 1
            return

        self.tries = 0
        self.packet_count += 1
        packet_json = json.loads(packet.json())
        dt = datetime.fromtimestamp(time.time())
        date_string = dt.strftime("%Y-%m-%d %I:%M:%S %p")
        packet.show()

        packet_data = {
            "time": date_string,
            "protocol": protocol,
            "src": packet_json.get("payload", {}).get("src", "Unknown"),
            "dst": packet_json.get("payload", {}).get("dst", "Unknown"),
            "size": packet_json.get("payload", {}).get("len", "Unknown"),
            "ttl": packet_json.get("payload", {}).get("ttl", "Unknown"),
        }
        # packet.show()
        self.packets.append(packet_data)

    def resolve_protocol(self, proto_number):
        try:
            return self.protocol_map[proto_number]
        except OSError:
            return str(proto_number)

    def display_packet(self, packet_data):
        self.tree.insert(
            "",
            tk.END,
            values=(
                packet_data["time"],
                packet_data["protocol"],
                packet_data["src"],
                packet_data["dst"],
                packet_data["size"],
                packet_data["ttl"],
            ),
        )

    def display_error(self, error_message):
        self.tree.insert("", tk.END, values=("Error", error_message, "", ""))


if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
