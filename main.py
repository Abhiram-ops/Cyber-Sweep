import os
import sys
import socket
import requests
import subprocess
import threading
import nmap
from scapy.all import ARP, Ether, srp
from cryptography.fernet import Fernet
from bs4 import BeautifulSoup
from datetime import datetime
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit, QLineEdit
from PyQt5.QtCore import Qt, QMetaType, QTextCursor

# Fix QTextCursor warning
QMetaType.registerType(QTextCursor)

BANNER = r'''
░█████╗░░██████╗░██╗░░░░░░░██╗███████╗███████╗██████╗░
██╔══██╗██╔════╝░██║░░██╗░░██║██╔════╝██╔════╝██╔══██╗
██║░░╚═╝╚█████╗░░╚██╗████╗██╔╝█████╗░░█████╗░░██████╔╝
██║░░██╗░╚═══██╗░░████╔═████║░██╔══╝░░██╔══╝░░██╔═══╝░
╚█████╔╝██████╔╝░░╚██╔╝░╚██╔╝░███████╗███████╗██║░░░░░
░╚════╝░╚═════╝░░░░╚═╝░░░╚═╝░░╚══════╝╚══════╝╚═╝░░░░░

                    CyberSweep
'''

def resolve_ip(target):
    try:
        ip = socket.gethostbyname(target)
        print(f"[+] Resolved IP: {ip}")
        return ip
    except Exception as e:
        print(f"[-] Failed to resolve IP: {e}")
        return None

def scan_ports(target):
    print("[~] Scanning ports using Nmap...")
    open_ports = []
    try:
        nm = nmap.PortScanner()
        nm.scan(target, '1-1000')
        for proto in nm[target].all_protocols():
            ports = nm[target][proto].keys()
            open_ports.extend(ports)
        print(f"[+] Open Ports: {open_ports}")
    except Exception as e:
        print(f"[-] Nmap port scanning failed: {e}")
    return open_ports

def fetch_headers(url):
    print("[~] Retrieving headers...")
    try:
        response = requests.get(url, timeout=5)
        for k, v in response.headers.items():
            print(f"    {k}: {v}")
        return response.headers
    except Exception as e:
        print(f"[-] Could not retrieve headers: {e}")
        return {}

def vulnerability_scan(url):
    print("[~] Performing basic vulnerability checks...")
    try:
        sqlmap_cmd = ["sqlmap", "-u", url, "--batch", "--crawl=1"]
        subprocess.run(sqlmap_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("[+] SQL injection scan complete (check sqlmap output).")
    except Exception as e:
        print(f"[-] Vulnerability checks failed: {e}")

def stealth_network_scan():
    print("[~] Performing stealth network scan with Scapy...")
    try:
        target_ip = "192.168.1.1/24"
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=2, verbose=0)[0]
        for sent, received in result:
            print(f"[+] Host: {received.psrc} | MAC: {received.hwsrc}")
    except Exception as e:
        print(f"[-] Scapy scan failed: {e}")

def run_scanner(url):
    print(BANNER)
    print(f"Enter the target URL (e.g. http://example.com): {url}\n")
    print(f"[~] Starting scan on {url}\n")
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]

    ip = resolve_ip(domain)
    if ip:
        scan_ports(ip)
    else:
        print("[-] Skipping port scan due to DNS failure.")

    fetch_headers(url)
    vulnerability_scan(url)
    stealth_network_scan()

def cli_mode():
    print(BANNER)
    url = input("Enter the target URL (e.g. http://example.com): ")
    run_scanner(url)

def gui_mode():
    class ScannerApp(QWidget):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("CyberSweep GUI")
            self.setGeometry(100, 100, 600, 400)
            layout = QVBoxLayout()

            self.url_input = QLineEdit(self)
            self.url_input.setPlaceholderText("Enter target URL")
            layout.addWidget(self.url_input)

            self.output = QTextEdit(self)
            self.output.setReadOnly(True)
            layout.addWidget(self.output)

            scan_btn = QPushButton("Start Scan", self)
            scan_btn.clicked.connect(self.start_scan)
            layout.addWidget(scan_btn)

            self.setLayout(layout)

        def start_scan(self):
            url = self.url_input.text()
            if url:
                self.output.append(f"[~] Starting scan on {url}\n")
                threading.Thread(target=self.scan, args=(url,), daemon=True).start()

        def scan(self, url):
            sys.stdout = self
            run_scanner(url)
            sys.stdout = sys.__stdout__

        def write(self, msg):
            self.output.append(str(msg))

        def flush(self):
            pass

    app = QApplication(sys.argv)
    win = ScannerApp()
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    if "--gui" in sys.argv:
        gui_mode()
    else:
        cli_mode()
        a9f1f25 (Initial commit)
