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
from fpdf import FPDF
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit, QLineEdit
from PyQt5.QtCore import Qt

BANNER = r'''
░█████╗░░██████╗░██╗░░░░░░░██╗███████╗███████╗██████╗░
██╔══██╗██╔════╝░██║░░██╗░░██║██╔════╝██╔════╝██╔══██╗
██║░░╚═╝╚█████╗░░╚██╗████╗██╔╝█████╗░░█████╗░░██████╔╝
██║░░██╗░╚═══██╗░░████╔═████║░██╔══╝░░██╔══╝░░██╔═══╝░
╚█████╔╝██████╔╝░░╚██╔╝░╚██╔╝░███████╗███████╗██║░░░░░
░╚════╝░╚═════╝░░░░╚═╝░░░╚═╝░░╚══════╝╚══════╝╚═╝░░░░░
                CyberSweep
'''

class ReportGenerator:
    def __init__(self, filename="CyberSweep_Report.pdf"):
        self.pdf = FPDF()
        self.filename = filename

    def header(self):
        self.pdf.set_font("Arial", "B", 16)
        self.pdf.cell(200, 10, "CyberSweep Scan Report", ln=True, align="C")
        self.pdf.set_font("Arial", "", 12)
        self.pdf.cell(200, 10, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
        self.pdf.ln(10)

    def add_section(self, title, content):
        self.pdf.set_font("Arial", "B", 14)
        self.pdf.cell(200, 10, title, ln=True)
        self.pdf.set_font("Arial", "", 12)
        if isinstance(content, list):
            for line in content:
                self.pdf.multi_cell(0, 10, str(line))
        else:
            self.pdf.multi_cell(0, 10, str(content))
        self.pdf.ln(5)

    def generate(self, data):
        self.pdf.add_page()
        self.header()
        for section, content in data.items():
            self.add_section(section, content)
        self.pdf.output(self.filename)


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
        nm = nmap.PortScanner(nmap_search_path=(r"C:\\Program Files (x86)\\Nmap\\nmap.exe",))

        nm.scan(target, '1-1000')
        for proto in nm[target].all_protocols():
            ports = nm[target][proto].keys()
            open_ports.extend(ports)
    except Exception as e:
        print(f"[-] Nmap port scanning failed: {e}")
    print(f"[+] Open Ports: {open_ports}")
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
    report_data = {"Target URL": url, "Scan Timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

    ip = resolve_ip(domain)
    report_data["Resolved IP"] = ip if ip else "Failed to resolve IP"

    open_ports = scan_ports(ip) if ip else []
    report_data["Open Ports"] = open_ports

    headers = fetch_headers(url)
    report_data["Response Headers"] = headers if headers else "Failed to retrieve headers"

    vulnerability_scan(url)
    report_data["Vulnerability Scan"] = "SQLMap scan attempted (check console output for details)"

    stealth_network_scan()
    report_data["Stealth Scan"] = "Scapy stealth scan attempted (check console output for details)"

    report = ReportGenerator()
    report.generate(report_data)
    print("[+] PDF report generated: CyberSweep_Report.pdf")

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
            self.output.append(msg)

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
