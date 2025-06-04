# 🛡️ Basic_Packet_Sniffer (Python + Scapy)

A powerful, GUI-based basic packet sniffer inspired by Wireshark. Built with Python, Scapy, and Tkinter, this tool captures and inspects network packets in real time.

---

## 🚀 Features

- 🧠 Real-time packet capture and inspection
- 🔍 Safe filter dropdown (TCP, UDP, ICMP, ARP, ports)
- 🧾 Dual-pane view: Encrypted (Hex) and Decrypted (ASCII)
- 📊 Protocol distribution pie chart
- 💾 Export captured data to `.pcap` and `.csv`
- 🖥️ Simple GUI built with Tkinter

---

## ⚙️ Installation

```bash
git clone https://github.com/yourusername/Basic_Packet_Sniffer.git
cd Basic_Packet_Sniffer
pip install -r requirements.txt

---

## 🧪 How to Run
Run with root privileges:

```bash
sudo python3 main.py

Use dropdown to choose a BPF-safe filter like tcp, udp, icmp, port 80, etc.

## 📂 Output Options:
 - 📁 Save packets as .pcap
 - 📊 Export data to .csv
 - 📉 Visualize live protocol usage

## 🤖 Powered By: 
 - Python
 - Scapy
 - Matplotlib
 - Tkinter
Built with the help of AI-assisted development using ChatGPT.
