import os
import sys
import socket
import requests
import subprocess
import threading
import webbrowser
import nmap
import urllib.parse
import asyncio # Added for asynchronous operations
import aiohttp   # Added for asynchronous HTTP requests
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

async def resolve_ip(target):
    print(f"[~] Attempting to resolve IP for {target}...")
    try:
        # Run synchronous socket operation in a separate thread
        ip = await asyncio.to_thread(socket.gethostbyname, target)
        print(f"[+] Resolved IP: {ip}")
        return ip
    except Exception as e:
        print(f"[-] Failed to resolve IP for {target}: {e}")
        return None

async def scan_ports(target):
    print(f"[~] Scanning ports for {target} using Nmap...")
    open_ports = []
    try:
        # Run synchronous nmap scan in a separate thread
        nm = nmap.PortScanner()
        # You might want to adjust the port range or add service detection for more power
        await asyncio.to_thread(nm.scan, target, '1-1000')
        if target in nm.all_hosts():
            for proto in nm[target].all_protocols():
                ports = nm[target][proto].keys()
                open_ports.extend(ports)
    except Exception as e:
        print(f"[-] Nmap port scanning failed for {target}: {e}")
    print(f"[+] Open Ports for {target}: {open_ports}")
    return open_ports

async def fetch_headers(url):
    print(f"[~] Retrieving headers for {url}...")
    headers_data = {}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                for k, v in response.headers.items():
                    print(f"    {k}: {v}")
                    headers_data[k] = v
        return headers_data
    except Exception as e:
        print(f"[-] Could not retrieve headers for {url}: {e}")
        return {}

async def vulnerability_scan_sqlmap(url):
    print(f"[~] Starting SQLMap vulnerability scan for {url}...")
    try:
        sqlmap_cmd = ["sqlmap", "-u", url, "--batch", "--crawl=1"]
        # Run synchronous subprocess in a separate thread
        await asyncio.to_thread(subprocess.run, sqlmap_cmd, capture_output=True, text=True, check=True)
        print("[+] SQLMap scan complete.")
    except subprocess.CalledProcessError as e:
        print(f"[-] SQLMap scan failed for {url}: {e.stderr}")
    except Exception as e:
        print(f"[-] SQLMap scan failed for {url}: {e}")

async def vulnerability_scan_burp(url):
    print(f"[~] Opening browser via Burp Suite proxy (127.0.0.1:8080) for {url}...")
    try:
        proxy_url = f"http://127.0.0.1:8080/{url.replace('http://', '').replace('https://', '')}"
        await asyncio.to_thread(webbrowser.open, proxy_url)
        print("[+] Burp-assisted scan started in your browser.")
    except Exception as e:
        print(f"[-] Burp-assisted scan failed for {url}: {e}")

async def stealth_network_scan():
    print("[~] Performing stealth network scan with Scapy...")
    try:
        target_ip = "192.168.1.1/24" # This needs to be adjusted to your network range
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        # Run synchronous scapy srp in a separate thread
        result, _ = await asyncio.to_thread(srp, packet, timeout=2, verbose=0)
        for sent, received in result:
            print(f"[+] Host: {received.psrc} | MAC: {received.hwsrc}")
    except Exception as e:
        print(f"[-] Scapy scan failed: {e}")

async def run_scanner(url, use_burp=False):
    print(BANNER)
    print(f"Target: {url}\n")

    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    report_data = {
        "Target URL": url,
        "Scan Timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    # Run network-bound and blocking operations concurrently
    ip_task = asyncio.create_task(resolve_ip(domain))
    headers_task = asyncio.create_task(fetch_headers(url))

    resolved_ip, headers = await asyncio.gather(ip_task, headers_task)

    report_data["Resolved IP"] = resolved_ip if resolved_ip else "Failed"
    report_data["Response Headers"] = headers if headers else "Failed"

    # Port scan depends on resolved IP
    open_ports = []
    if resolved_ip:
        open_ports = await scan_ports(resolved_ip)
    report_data["Open Ports"] = open_ports

    # Vulnerability scans and stealth scan can also run concurrently
    vulnerability_scan_task = None
    if use_burp:
        vulnerability_scan_task = asyncio.create_task(vulnerability_scan_burp(url))
        report_data["Vulnerability Scan"] = "Burp-assisted scan initiated (manual interception recommended)."
    else:
        vulnerability_scan_task = asyncio.create_task(vulnerability_scan_sqlmap(url))
        report_data["Vulnerability Scan"] = "SQLMap scan attempted."

    stealth_scan_task = asyncio.create_task(stealth_network_scan())

    # Wait for all remaining tasks to complete
    if vulnerability_scan_task:
        await vulnerability_scan_task
    await stealth_scan_task


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
    asyncio.run(run_scanner(url, use_burp)) # Run the async main function

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
            # Run the async function in a separate thread to not block the GUI
            threading.Thread(target=lambda: asyncio.run(self.scan(url, use_burp)), daemon=True).start()

        async def scan(self, url, use_burp):
            # Redirect stdout to the QTextEdit
            original_stdout = sys.stdout
            sys.stdout = self

            try:
                await run_scanner(url, use_burp)
            finally:
                # Restore original stdout
                sys.stdout = original_stdout


        def write(self, msg):
            # Ensure text is appended in the main GUI thread
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