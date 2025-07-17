import os
import sys
import socket
import requests
import subprocess
import threading
import webbrowser
import nmap
import urllib.parse # Added import for URL parsing
from scapy.all import ARP, Ether, srp
from cryptography.fernet import Fernet
from bs4 import BeautifulSoup
from datetime import datetime
from fpdf import FPDF
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit, QLineEdit, QCheckBox
)
from PyQt5.QtCore import Qt
import time

# ASCII Banner
BANNER = r'''
░█████╗░░██████╗░██╗░░░░░░░██╗███████╗███████╗██████╗░
██╔══██╗██╔════╝░██║░░██╗░░██║██╔════╝██╔════╝██╔══██╗
██║░░╚═╝╚█████╗░░╚██╗████╗██╔╝█████╗░░█████╗░░██████╔╝
██║░░██╗░╚═══██╗░░████╔═████║░██╔══╝░░██╔══╝░░██╔═══╝░
╚█████╔╝██████╔╝░░╚██╔╝░╚██╔╝░███████╗███████╗██║░░░░░
░╚════╝░╚═════╝░░░░╚═╝░░░╚═╝░░╚══════╝╚══════╝╚═╝░░░░░
                CyberSweep
'''

def loading_animation(message="Launching CSweep...", duration=3):
    for _ in range(duration * 10):
        for frame in "|/-\\":
            sys.stdout.write(f"\r{message} {frame}")
            sys.stdout.flush()
            time.sleep(0.1)
    sys.stdout.write("\r" + " " * (len(message) + 2) + "\r")

# Show loading animation before launch
loading_animation()

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

def is_valid_url(url):
    """
    Checks if a given string is a valid URL with a scheme and network location.
    """
    try:
        result = urllib.parse.urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

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

def vulnerability_scan_sqlmap(url):
    print("[~] Starting SQLMap vulnerability scan...")
    try:
        sqlmap_cmd = ["sqlmap", "-u", url, "--batch", "--crawl=1"]
        subprocess.run(sqlmap_cmd)
        print("[+] SQLMap scan complete.")
    except Exception as e:
        print(f"[-] SQLMap scan failed: {e}")

def vulnerability_scan_burp(url):
    print("[~] Opening browser via Burp Suite proxy (127.0.0.1:8080)...")
    try:
        proxy_url = f"http://127.0.0.1:8080/{url.replace('http://', '').replace('https://', '')}"
        webbrowser.open(proxy_url)
        print("[+] Burp-assisted scan started in your browser.")
    except Exception as e:
        print(f"[-] Burp-assisted scan failed: {e}")

def stealth_network_scan():
    print("[~] Performing stealth network scan with Scapy...")
    try:
        target_ip = "192.168.1.1/24" # This needs to be adjusted to your network range
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=2, verbose=0)[0]
        for sent, received in result:
            print(f"[+] Host: {received.psrc} | MAC: {received.hwsrc}")
    except Exception as e:
        print(f"[-] Scapy scan failed: {e}")

def run_scanner(url, use_burp=False):
    print(BANNER)
    print(f"Target: {url}\n")

    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    report_data = {
        "Target URL": url,
        "Scan Timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    ip = resolve_ip(domain)
    report_data["Resolved IP"] = ip if ip else "Failed"

    open_ports = scan_ports(ip) if ip else []
    report_data["Open Ports"] = open_ports

    headers = fetch_headers(url)
    report_data["Response Headers"] = headers if headers else "Failed"

    if use_burp:
        vulnerability_scan_burp(url)
        report_data["Vulnerability Scan"] = "Burp-assisted scan initiated (manual interception recommended)."
    else:
        vulnerability_scan_sqlmap(url)
        report_data["Vulnerability Scan"] = "SQLMap scan attempted."

    stealth_network_scan()
    report_data["Stealth Scan"] = "Scapy scan attempted."

    report = ReportGenerator()
    report.generate(report_data)
    print("[+] PDF report generated: CyberSweep_Report.pdf")

def cli_mode():
    print(BANNER)
    url = input("Enter target URL (e.g. http://example.com): ").strip()
    if not is_valid_url(url):
        print("[-] Error: Invalid URL format. Please include http:// or https:// and a valid domain.")
        return # Exit or re-prompt, depending on desired behavior
    use_burp = input("Use Burp Suite for vulnerability scan? (y/n): ").strip().lower() == "y"
    run_scanner(url, use_burp)

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

            self.burp_checkbox = QCheckBox("Use Burp Suite for vulnerability scan")
            layout.addWidget(self.burp_checkbox)

            self.output = QTextEdit(self)
            self.output.setReadOnly(True)
            layout.addWidget(self.output)

            scan_btn = QPushButton("Start Scan", self)
            scan_btn.clicked.connect(self.start_scan)
            layout.addWidget(scan_btn)
            self.setLayout(layout)

        def start_scan(self):
            url = self.url_input.text().strip()
            if not is_valid_url(url):
                self.output.append("[-] Error: Invalid URL format. Please include http:// or https:// and a valid domain.")
                return # Stop the scan if URL is invalid
            self.output.append(f"[~] Starting scan on {url}\n")
            use_burp = self.burp_checkbox.isChecked()
            threading.Thread(target=self.scan, args=(url, use_burp), daemon=True).start()

        def scan(self, url, use_burp):
            sys.stdout = self
            run_scanner(url, use_burp)
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