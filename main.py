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
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QTextCursor
from fpdf import FPDF


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
    print("[~] Performing basic vulnerability checks using SQLMap...")
    try:
        sqlmap_cmd = ["sqlmap", "-u", url, "--batch", "--crawl=1"]
        subprocess.run(sqlmap_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("[+] SQL injection scan complete.")
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
class ReportGenerator:
    def __init__(self):
        self.pdf = FPDF()
        self.pdf.add_page()
        self.pdf.set_font("Arial", size=12)

    def add_title(self, title):
        self.pdf.set_font("Arial", 'B', size=16)
        self.pdf.cell(200, 10, txt=title, ln=True, align='C')
        self.pdf.set_font("Arial", size=12)

    def add_line(self, line):
        self.pdf.multi_cell(0, 10, txt=line)

    def save(self, filename):
        self.pdf.output(filename)

def generate_report(scan_data):
    report = ReportGenerator()
    report.add_title("CyberSweep Scan Report")
    report.add_line(f"Scan Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.add_line(f"Target URL: {scan_data['url']}")
    report.add_line(f"Resolved IP: {scan_data.get('ip', 'N/A')}")
    report.add_line(f"\nOpen Ports: {scan_data.get('ports', [])}")
    report.add_line("\nHTTP Headers:")
    headers = scan_data.get('headers', {})
    if headers:
        for k, v in headers.items():
            report.add_line(f"{k}: {v}")
    else:
        report.add_line("No headers retrieved.")
    report.add_line("\nVulnerability Scan Status: " + scan_data.get('vuln_status', 'Not performed'))

    report.add_line("\nStealth Network Scan:")
    for host in scan_data.get('stealth_hosts', []):
        report.add_line(f"Host: {host['ip']} | MAC: {host['mac']}")

    filename = f"CyberSweep_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    report.save(filename)
    print(f"[+] Report saved as {filename}")


def cli_mode():
    print(BANNER)
    url = input("Enter the target URL (e.g. http://example.com): ")
    run_scanner(url)

def gui_mode():
    class ScannerApp(QWidget):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("CyberSweep GUI")
            self.setGeometry(100, 100, 700, 500)
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
                self.output.clear()
                self.output.append(f"[~] Starting scan on {url}\n")
                threading.Thread(target=self.scan, args=(url,), daemon=True).start()

        def scan(self, url):
            sys.stdout = self
            try:
                run_scanner(url)
            finally:
                sys.stdout = sys.__stdout__

        def write(self, msg):
            self.output.moveCursor(QTextCursor.End)
            self.output.insertPlainText(msg)

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
