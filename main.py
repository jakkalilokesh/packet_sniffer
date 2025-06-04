
import socket
import threading
import tkinter as tk
from tkinter import ttk, filedialog
from datetime import datetime
from scapy.all import sniff, wrpcap
from scapy.layers.inet import IP
import matplotlib.pyplot as plt
from collections import Counter
import csv

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Wireshark-Style Packet Sniffer")
        self.running = False
        self.packet_data = []
        self.bpf_filter = tk.StringVar(value="tcp")

        # Top bar with filter
        top_frame = tk.Frame(root)
        top_frame.pack(pady=5)
        tk.Label(top_frame, text="Filter (BPF):").pack(side=tk.LEFT)
        self.filter_menu = ttk.Combobox(top_frame, textvariable=self.bpf_filter,
                                        values=["tcp", "udp", "icmp", "arp", "port 53", "port 80", "port 443", "tcp or udp or icmp"],
                                        width=30)
        self.filter_menu.pack(side=tk.LEFT, padx=5)
        tk.Button(top_frame, text="Start", command=self.start_sniffing, bg="green").pack(side=tk.LEFT, padx=5)
        tk.Button(top_frame, text="Stop", command=self.stop_sniffing, bg="red").pack(side=tk.LEFT, padx=5)
        tk.Button(top_frame, text="Save PCAP", command=self.save_pcap).pack(side=tk.LEFT, padx=5)
        tk.Button(top_frame, text="Export CSV", command=self.save_csv).pack(side=tk.LEFT, padx=5)
        tk.Button(top_frame, text="Graph", command=self.show_graph).pack(side=tk.LEFT, padx=5)

        # Packet Table
        self.tree = ttk.Treeview(root, columns=("time", "src", "dst", "proto", "len"), show='headings', height=18)
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col.upper())
        self.tree.pack(padx=10, pady=5)
        self.tree.bind("<<TreeviewSelect>>", self.display_packet)

        # Bottom pane: encrypted vs decrypted
        bottom = tk.Frame(root)
        bottom.pack(padx=10, pady=5)
        tk.Label(bottom, text="Encrypted Packet (Hex)").grid(row=0, column=0)
        tk.Label(bottom, text="Decrypted Packet (ASCII)").grid(row=0, column=1)

        self.hex_view = tk.Text(bottom, width=80, height=10, bg="black", fg="lime", font=("Consolas", 9))
        self.hex_view.grid(row=1, column=0, padx=5)

        self.ascii_view = tk.Text(bottom, width=80, height=10, bg="black", fg="cyan", font=("Consolas", 9))
        self.ascii_view.grid(row=1, column=1, padx=5)

    def start_sniffing(self):
        self.running = True
        self.packet_data = []
        threading.Thread(target=self.sniff_packets, daemon=True).start()

    def stop_sniffing(self):
        self.running = False

    def sniff_packets(self):
        def handle(pkt):
            if not self.running:
                return
            if IP in pkt:
                ts = datetime.now().strftime("%H:%M:%S")
                src = pkt[IP].src
                dst = pkt[IP].dst
                proto = pkt.lastlayer().name
                size = len(pkt)
                self.packet_data.append((ts, src, dst, proto, size, bytes(pkt)))
                self.tree.insert('', tk.END, values=(ts, src, dst, proto, size))
        try:
            sniff(filter=self.bpf_filter.get(), prn=handle, store=0)
        except Exception as e:
            self.hex_view.insert("end", f"[!] Error: {e}\n")

    def display_packet(self, _):
        self.hex_view.delete(1.0, tk.END)
        self.ascii_view.delete(1.0, tk.END)
        selected = self.tree.focus()
        index = self.tree.index(selected)
        if index < len(self.packet_data):
            raw = self.packet_data[index][5]
            hex_lines = [raw[i:i+16] for i in range(0, len(raw), 16)]
            for line in hex_lines:
                self.hex_view.insert(tk.END, ' '.join(f"{b:02x}" for b in line) + "\n")
                self.ascii_view.insert(tk.END, ''.join(chr(b) if 32 <= b < 127 else '.' for b in line) + "\n")

    def save_pcap(self):
        if not self.packet_data:
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".pcap")
        if file_path:
            wrpcap(file_path, [pkt[5] for pkt in self.packet_data])

    def save_csv(self):
        if not self.packet_data:
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".csv")
        if file_path:
            with open(file_path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Time", "Source", "Destination", "Protocol", "Length"])
                for pkt in self.packet_data:
                    writer.writerow(pkt[:5])

    def show_graph(self):
        counter = Counter(pkt[3] for pkt in self.packet_data)
        labels, sizes = zip(*counter.items()) if counter else ([], [])
        plt.figure(figsize=(6,6))
        plt.pie(sizes, labels=labels, autopct="%1.1f%%")
        plt.title("Protocol Distribution")
        plt.show()

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
