import os
import sys
import socket
import subprocess
import threading
import webbrowser
import nmap
import urllib.parse
import asyncio
import aiohttp
import re # Added for sensitive data scanning regex
from scapy.all import ARP, Ether, srp
from bs4 import BeautifulSoup
from datetime import datetime
from fpdf import FPDF
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit, QLineEdit, QCheckBox, QMessageBox
)
from PyQt5.QtCore import Qt
import time

# --- Database specific imports (you will need to install these) ---
# import pymysql.cursors # For MySQL: pip install pymysql
# import psycopg2.extras # For PostgreSQL: pip install psycopg2-binary
# import pyodbc # For MSSQL/ODBC: pip install pyodbc
# -----------------------------------------------------------------

# ASCII Banner
BANNER = r'''
░█████╗░░██████╗░██╗░░░░░░░██╗███████╗███████╗██████╗░
██╔══██╗██╔════╝░██║░░██╗░░██║██╔════╝██╔════╝██╔══██╗
██║░░╚═╝╚█████╗░░╚██╗████╗██╔╝█████╗░░█████╗░░██████╔╝
██║░░██╗░╚═══██╗░░████╔═████║░██╔══╝░░██╔══╝░░██╔═══╝░
╚█████╔╝██████╔╝░░╚██╔╝░╚██╔╝░███████╗███████╗██║░░░░░
░╚════╝░╚═════╝░░░░╚═╝░░░╚╚══════╝╚══════╝╚═╝░░░░░
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
            if content and (isinstance(content, list) and len(content) > 0 or (isinstance(content, str) and content.strip() != "") or not isinstance(content, (list, str))):
                self.add_section(section, content)
        self.pdf.output(self.filename)

def is_valid_url(url):
    """
    Checks if a given string is a valid URL with a scheme and network location.
    """
    try:
        result = urllib.parse.urlparse(url)
        # Ensure scheme (http/https) and network location (domain) are present
        return all([result.scheme in ['http', 'https'], result.netloc])
    except ValueError:
        return False

async def resolve_ip(target):
    print(f"[~] Attempting to resolve IP for {target}...")
    try:
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
        nm = nmap.PortScanner()
        common_ports = '21,22,23,25,80,110,135,139,443,445,3306,3389,5432,1433,8080,8443' # Added common DB ports
        await asyncio.to_thread(nm.scan, target, common_ports)

        if target in nm.all_hosts():
            for proto in nm[target].all_protocols():
                ports = nm[target][proto].keys()
                for port in sorted(ports):
                    state = nm[target][proto][port]['state']
                    service = nm[target][proto][port].get('name', 'unknown')
                    product = nm[target][proto][port].get('product', '')
                    version = nm[target][proto][port].get('version', '')
                    if state == 'open':
                        detail = f"(Service: {service}"
                        if product: detail += f", Product: {product}"
                        if version: detail += f", Version: {version}"
                        detail += ")"
                        open_ports.append(f"Port {port}/{proto} is OPEN {detail}")
    except Exception as e:
        print(f"[-] Nmap port scanning failed for {target}: {e}")
    print(f"[+] Open Ports for {target}:")
    for p in open_ports:
        print(f"    {p}")
    return open_ports

async def fetch_headers(url):
    print(f"[~] Retrieving headers for {url}...")
    headers_data = {}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                for k, v in response.headers.items():
                    print(f"    {k}: {v}")
                    headers_data[k] = v
        return headers_data
    except Exception as e:
        print(f"[-] Could not retrieve headers for {url}: {e}")
        return {}

async def analyze_security_headers(headers):
    print("[~] Analyzing security headers...")
    security_issues = []

    if not headers:
        security_issues.append("No headers retrieved for analysis.")
        return security_issues

    expected_headers = {
        "Strict-Transport-Security": "Missing HSTS header. Should enforce HTTPS.",
        "X-Content-Type-Options": "Missing X-Content-Type-Options header. Should be 'nosniff'.",
        "X-Frame-Options": "Missing X-Frame-Options header. Should be 'DENY' or 'SAMEORIGIN'.",
        "Content-Security-Policy": "Missing Content-Security-Policy (CSP) header. Provides defense against XSS and data injection attacks.",
        "Referrer-Policy": "Missing Referrer-Policy header. Controls how much referrer information is sent.",
        "Permissions-Policy": "Missing Permissions-Policy header. Controls browser features and APIs for the page."
    }

    found_headers = {k.lower(): v for k, v in headers.items()}

    for header, warning in expected_headers.items():
        if header.lower() not in found_headers:
            security_issues.append(f"WARNING: {warning}")
        else:
            if header.lower() == "x-content-type-options" and "nosniff" not in found_headers[header.lower()].lower():
                security_issues.append(f"WARNING: X-Content-Type-Options found but 'nosniff' is missing/incorrect.")
            if header.lower() == "x-frame-options" and found_headers[header.lower()].lower() not in ["deny", "sameorigin"]:
                security_issues.append(f"WARNING: X-Frame-Options found but value '{found_headers[header.lower()]}' is not 'DENY' or 'SAMEORIGIN'.")

    if not security_issues:
        security_issues.append("No significant missing security headers detected (basic check).")

    print("[+] Security header analysis complete.")
    for issue in security_issues:
        print(f"    - {issue}")
    return security_issues

async def scan_xss(url):
    print(f"[~] Performing basic XSS scan on {url}...")
    xss_findings = []
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "\"-alert('XSS')-\"",
        "'</script><script>alert('XSS')</script>'",
        "<img src=x onerror=alert(1)>",
        "<body onload=alert(1)>",
        "<svg onload=alert(1)>",
    ]

    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)

    if not query_params:
        print("[-] No query parameters found for XSS injection. Skipping basic XSS scan.")
        return ["No query parameters found for XSS injection (skipped)."]

    async with aiohttp.ClientSession() as session:
        tasks = []
        for param, values in query_params.items():
            # Create a task for each payload for each parameter
            for payload in xss_payloads:
                async def _check_xss_payload(p, v, payload_str):
                    test_params = query_params.copy()
                    test_params[p] = payload_str
                    encoded_test_query = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = parsed_url._replace(query=encoded_test_query).geturl()

                    try:
                        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                            response_text = await response.text()
                            if payload_str in response_text or urllib.parse.quote(payload_str) in response_text:
                                finding = f"Possible Reflected XSS in parameter '{p}' with payload: {payload_str}. Check URL: {test_url}"
                                xss_findings.append(finding)
                                print(f"[!] {finding}")
                    except Exception:
                        pass # Suppress common connection errors for cleaner output
                tasks.append(_check_xss_payload(param, values, payload))
        await asyncio.gather(*tasks, return_exceptions=True)

    if not xss_findings:
        xss_findings.append("No obvious reflected XSS vulnerabilities found (basic check).")

    print("[+] XSS scan complete.")
    return xss_findings

async def scan_directory_traversal(url):
    print(f"[~] Performing directory traversal/brute-force scan on {url}...")
    found_paths = []
    common_paths = [
        "admin/", "dashboard/", "login/", "wp-admin/", "phpmyadmin/",
        "robots.txt", "sitemap.xml", ".env", ".git/HEAD", "backup.zip",
        "test/", "dev/", "config/", "assets/", "js/", "css/",
        "index.bak", "index.php.bak", "wp-config.php.bak", "config.php.bak",
        "README.md", "LICENSE.txt", ".htaccess", ".bash_history",
        "web.config", "server-status", "info.php",
    ]

    parsed_url = urllib.parse.urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"

    async with aiohttp.ClientSession() as session:
        tasks = []
        for path in common_paths:
            full_path = urllib.parse.urljoin(base_url, path)
            tasks.append(asyncio.create_task(
                check_path_status(session, full_path, path, found_paths)
            ))
        await asyncio.gather(*tasks, return_exceptions=True)

    if not found_paths:
        found_paths.append("No common directories/files found (basic brute-force).")

    print("[+] Directory traversal/brute-force scan complete.")
    return found_paths

async def check_path_status(session, full_path, original_path, found_paths_list):
    try:
        async with session.get(full_path, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=5)) as response:
            if response.status == 200:
                finding = f"Found: {full_path} (Status: {response.status})"
                print(f"[!] {finding}")
                found_paths_list.append(finding)
            elif 300 <= response.status < 400:
                location = response.headers.get('Location', 'N/A')
                finding = f"Redirect: {full_path} (Status: {response.status}) -> {location}"
                print(f"[?] {finding}")
                found_paths_list.append(finding)
            elif response.status == 401 or response.status == 403:
                finding = f"Forbidden/Unauthorized: {full_path} (Status: {response.status})"
                print(f"[-] {finding}")
                found_paths_list.append(finding)
    except aiohttp.ClientError:
        pass
    except Exception as e:
        print(f"[-] Unexpected error checking {full_path}: {e}")

async def vulnerability_scan_sqlmap(url):
    print(f"[~] Starting SQLMap vulnerability scan for {url}...")
    sqlmap_output = []
    try:
        sqlmap_cmd = ["sqlmap", "-u", url, "--batch", "--crawl=2", "--forms", "--dbs"]
        process = await asyncio.to_thread(subprocess.run, sqlmap_cmd, capture_output=True, text=True, check=False)

        if process.returncode == 0:
            sqlmap_output.append("SQLMap scan completed successfully.")
            if "vulnerable" in process.stdout.lower() or "vulnerable" in process.stderr.lower():
                sqlmap_output.append("!!! POSSIBLE SQL INJECTION VULNERABILITY DETECTED BY SQLMAP !!!")
                detailed_findings = []
                for line in process.stdout.splitlines():
                    if "payload" in line.lower() or "parameter" in line.lower() and ("vulnerable" in line.lower() or "type" in line.lower()):
                        detailed_findings.append(line.strip())
                if detailed_findings:
                    sqlmap_output.extend(detailed_findings)
                else:
                    sqlmap_output.append("Review SQLMap's full output for details.")

                db_match = re.search(r'available databases \| \((\d+)\): (.+)', process.stdout, re.IGNORECASE)
                if db_match:
                    dbs_found = db_match.group(2)
                    sqlmap_output.append(f"SQLMap found databases: {dbs_found}")

            else:
                sqlmap_output.append("SQLMap did not report any obvious SQL Injection vulnerabilities.")
        else:
            sqlmap_output.append(f"SQLMap scan finished with errors or no vulnerabilities reported (Exit Code: {process.returncode}).")
            sqlmap_output.append("--- SQLMap Error/Partial Output ---")
            output_lines = (process.stdout + process.stderr).splitlines()
            sqlmap_output.extend([line for line in output_lines if line.strip()][-10:])

        for line in sqlmap_output:
            if line.strip():
                print(line)

    except FileNotFoundError:
        sqlmap_output.append("[-] Error: SQLMap command not found. Please ensure SQLMap is installed and in your system's PATH.")
        print(sqlmap_output[-1])
    except Exception as e:
        sqlmap_output.append(f"[-] An unexpected error occurred during SQLMap scan: {e}")
        print(sqlmap_output[-1])

    return sqlmap_output

async def vulnerability_scan_burp(url):
    print(f"[~] Opening browser to {url} for Burp Suite interception (127.0.0.1:8080)...")
    print("[!] IMPORTANT: Ensure your browser is configured to use Burp Suite as a proxy (127.0.0.1:8080) BEFORE starting the scan.")
    try:
        await asyncio.to_thread(webbrowser.open, url)
        print("[+] Browser opened to target URL. Burp-assisted scan initiated (manual interception recommended in Burp Suite).")
        return [f"Browser opened to {url}. Manual interception required in Burp Suite (configured on 127.0.0.1:8080)."]
    except Exception as e:
        print(f"[-] Failed to open browser for Burp-assisted scan: {e}")
        return [f"Failed to open browser for Burp-assisted scan: {e}"]

async def stealth_network_scan():
    print("[~] Performing stealth network scan with Scapy (ARP)...")
    scapy_findings = []
    try:
        target_ip_range = "192.168.1.1/24" # WARNING: Adjust this to YOUR local network range
        print(f"[!] Scanning local network range: {target_ip_range}. Please adjust this in code if incorrect or for a different subnet.")

        arp = ARP(pdst=target_ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        answered, unanswered = await asyncio.to_thread(srp, packet, timeout=5, verbose=0)

        for sent, received in answered:
            finding = f"Host: {received.psrc} | MAC: {received.hwsrc} (Found via ARP)"
            scapy_findings.append(finding)
            print(f"[+] {finding}")

        if not scapy_findings:
            scapy_findings.append("No active hosts found on the specified local network range (basic ARP scan).")

    except PermissionError:
        scapy_findings.append("[-] Permission denied for Scapy scan. Run as root/administrator or check network permissions.")
        print(scapy_findings[-1])
    except ImportError:
        scapy_findings.append("[-] Scapy not fully installed or missing dependencies (e.g., Npcap/WinPcap for Windows). Cannot perform network scan.")
        print(scapy_findings[-1])
    except Exception as e:
        scapy_findings.append(f"[-] Scapy scan failed: {e}")
        print(scapy_findings[-1])

    return scapy_findings

async def check_for_database_access(ip, open_ports_details):
    """
    Attempts to connect to common database services if their ports are open.
    NOTE: This is a placeholder. Real implementation requires specific DB drivers.
    """
    print(f"[~] Checking for database access on {ip} based on open ports...")
    db_access_results = []
    common_db_ports = {
        3306: "MySQL",
        5432: "PostgreSQL",
        1433: "MSSQL"
    }
    default_credentials = [
        ("root", ""), ("root", "root"), ("admin", "admin"), ("admin", ""),
        ("postgres", "postgres"), ("postgres", ""),
        ("sa", "password"), ("sa", "")
    ]

    found_db_ports = []
    for port_detail in open_ports_details:
        for port_num, db_type in common_db_ports.items():
            if f"Port {port_num}/tcp is OPEN" in port_detail: # Check if port is explicitly mentioned as open TCP
                # Also check for product/service detected by nmap, if available in the detail string
                if db_type.lower() in port_detail.lower():
                    found_db_ports.append((ip, port_num, db_type))
                    break # Move to next port detail once a match is found

    if not found_db_ports:
        db_access_results.append("No common database ports detected as open. Skipping database access attempts.")
        print(db_access_results[-1])
        return db_access_results
    
    tasks = []
    for ip_addr, port, db_type in found_db_ports:
        for username, password in default_credentials:
            tasks.append(asyncio.create_task(
                attempt_db_connection(ip_addr, port, db_type, username, password, db_access_results)
            ))
    await asyncio.gather(*tasks, return_exceptions=True) # Run all connection attempts concurrently

    if not db_access_results: # If no results were appended from successful/failed attempts
        db_access_results.append("No common database ports found open or all connection attempts failed.")

    print("[+] Database access attempts complete.")
    return db_access_results

async def attempt_db_connection(ip, port, db_type, username, password, results_list):
    """Helper to attempt a single database connection."""
    try:
        # NOTE: THIS IS A PLACEHOLDER FOR ACTUAL DATABASE CONNECTION LOGIC
        # You would need to install specific Python database drivers (e.g., pymysql, psycopg2, pyodbc)
        # and replace this with actual connection code.
        # Example for MySQL (requires 'pymysql'):
        # import pymysql
        # conn = await asyncio.to_thread(pymysql.connect, host=ip, port=port,
        #                                user=username, password=password,
        #                                database='mysql', # Try a common default database name
        #                                autocommit=True, connect_timeout=3)
        # conn.close()
        #
        # Example for PostgreSQL (requires 'psycopg2-binary'):
        # import psycopg2
        # conn = await asyncio.to_thread(psycopg2.connect, host=ip, port=port,
        #                                user=username, password=password,
        #                                dbname='postgres', # Try a common default database name
        #                                connect_timeout=3)
        # conn.close()
        
        # Simulate a connection attempt success/failure
        # In a real scenario, this would be a network connection attempt
        # For demonstration, we'll just log the attempt.
        if username == "root" and password == "": # Example: simulate success for this default combo
            success_msg = f"SUCCESS: Connected to {db_type} on {ip}:{port} with user '{username}' and password '{password}' (Simulated success)."
            results_list.append(success_msg)
            print(f"[+] {success_msg}")
        else:
            fail_msg = f"FAILED: {db_type} on {ip}:{port} with user '{username}' and password '{password}' (Simulated failure)."
            results_list.append(fail_msg)
            # print(f"    {fail_msg}") # Suppress for brevity in normal output
            
    except Exception as e:
        error_msg = f"ERROR: Could not connect to {db_type} on {ip}:{port} with user '{username}' and password '{password}': {e}"
        results_list.append(error_msg)
        # print(f"    {error_msg}") # Suppress for brevity in normal output

async def comprehensive_web_crawler(base_url, max_pages=50, max_depth=2):
    print(f"[~] Starting comprehensive web crawl from {base_url} (Max pages: {max_pages}, Max depth: {max_depth})...")
    
    # Store visited URLs and their content
    crawled_data = []
    
    # Use a set to keep track of visited URLs to avoid redundant fetches and loops
    visited_urls = set()
    # Use a queue for BFS-like crawling (URL, current_depth)
    urls_to_visit = asyncio.Queue()

    await urls_to_visit.put((base_url, 0))
    visited_urls.add(base_url)

    async with aiohttp.ClientSession() as session:
        while not urls_to_visit.empty() and len(crawled_data) < max_pages:
            current_url, current_depth = await urls_to_visit.get()
            print(f"[~] Crawling: {current_url} (Depth: {current_depth})")

            try:
                async with session.get(current_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status == 200:
                        content_type = response.headers.get('Content-Type', '').lower()
                        if 'text/html' in content_type:
                            html_content = await response.text()
                            crawled_data.append({"url": current_url, "content": html_content})

                            if current_depth < max_depth:
                                soup = BeautifulSoup(html_content, 'html.parser')
                                for link in soup.find_all('a', href=True):
                                    href = link.get('href')
                                    absolute_url = urllib.parse.urljoin(current_url, href)
                                    parsed_absolute_url = urllib.parse.urlparse(absolute_url)

                                    # Only follow links on the same domain and not already visited
                                    if parsed_absolute_url.netloc == urllib.parse.urlparse(base_url).netloc and \
                                       absolute_url not in visited_urls:
                                        visited_urls.add(absolute_url)
                                        await urls_to_visit.put((absolute_url, current_depth + 1))
                        else:
                            # For non-HTML content, just record the URL
                            crawled_data.append({"url": current_url, "content": f"Non-HTML content ({content_type})"})
                    else:
                        print(f"[-] Failed to crawl {current_url}: HTTP Status {response.status}")
                        crawled_data.append({"url": current_url, "content": f"HTTP Status {response.status}"})

            except Exception as e:
                print(f"[-] Error crawling {current_url}: {e}")
                crawled_data.append({"url": current_url, "content": f"Error: {e}"})
            
            # Small delay to be polite to the server and avoid rate limiting
            await asyncio.sleep(0.1)

    print(f"[+] Web crawl complete. Discovered {len(crawled_data)} unique URLs.")
    return crawled_data

def scan_for_sensitive_data(text_content):
    """
    Scans text content for common patterns of sensitive data.
    """
    sensitive_findings = []

    # Regex patterns for sensitive data
    # IMPORTANT: These patterns are basic and might produce false positives/negatives.
    # For robust production use, more sophisticated validation (e.g., checksums for credit cards) is needed.
    
    # Email addresses
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    emails = re.findall(email_pattern, text_content)
    for email in emails:
        sensitive_findings.append(f"Email Address: {email}")

    # Basic Credit Card Numbers (simplified, for demonstration only!)
    # Does NOT validate checksums (e.g., Luhn algorithm)
    # Visa: 4[0-9]{12}(?:[0-9]{3})?
    # MasterCard: 5[1-5][0-9]{14}
    # Amex: 3[47][0-9]{13}
    # Discover: 6(?:011|5[0-9]{2})[0-9]{12}
    cc_pattern = r'\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b'
    credit_cards = re.findall(cc_pattern, text_content)
    for cc in credit_cards:
        sensitive_findings.append(f"Possible Credit Card (Basic): {cc}")

    # API Keys / Tokens (very generic, prone to false positives)
    api_key_patterns = [
        r'(?:api_key|apikey|token|auth|secret|client_id|client_secret|access_token|bearer)[=\s"\']{0,2}[a-zA-Z0-9_-]{16,}',
        r'[A-Za-z0-9]{32,64}(?:[_-]key|[_-]token)?' # Generic hex/base64-like strings that might be keys
    ]
    for pattern in api_key_patterns:
        keys = re.findall(pattern, text_content, re.IGNORECASE)
        for key in keys:
            sensitive_findings.append(f"Possible API Key/Token: {key}")

    # IP addresses (v4 basic)
    ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ipv4_addresses = re.findall(ipv4_pattern, text_content)
    for ip in ipv4_addresses:
        # Exclude common private/loopback for less noise, or known public ones.
        if not (ip.startswith('127.') or ip.startswith('10.') or ip.startswith('172.16.') or ip.startswith('192.168.')):
            sensitive_findings.append(f"IPv4 Address: {ip}")
    
    # Common database connection strings (highly generalized)
    db_conn_pattern = r'(mysql|postgresql|mongodb|odbc|sqlserver):\/\/[^\s\'"]+'
    db_conns = re.findall(db_conn_pattern, text_content, re.IGNORECASE)
    for db_conn in db_conns:
        sensitive_findings.append(f"Possible DB Connection String: {db_conn[0]}://...") # db_conn is tuple (type, string)

    return sensitive_findings


async def run_scanner(url, use_burp=False, proceed_db_scan=False, do_comprehensive_crawl=False):
    print(BANNER)
    print(f"Target: {url}\n")

    parsed_url = urllib.parse.urlparse(url)
    domain = parsed_url.netloc

    report_data = {
        "Target URL": url,
        "Scan Timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    # Run core reconnaissance tasks concurrently
    ip_task = asyncio.create_task(resolve_ip(domain))
    headers_task = asyncio.create_task(fetch_headers(url))

    resolved_ip = await ip_task
    headers = await headers_task

    report_data["Resolved IP"] = resolved_ip if resolved_ip else "Failed"
    report_data["Response Headers"] = headers if headers else "Failed"

    tasks = []
    
    # Conditional tasks based on resolved_ip
    open_ports_results = []
    if resolved_ip:
        open_ports_task = asyncio.create_task(scan_ports(resolved_ip))
        tasks.append(open_ports_task)
    else:
        report_data["Open Ports"] = ["Skipped due to no resolved IP."]

    # Always run security header analysis (if headers were fetched)
    security_headers_task = asyncio.create_task(analyze_security_headers(headers))
    tasks.append(security_headers_task)

    # XSS scan
    xss_scan_task = asyncio.create_task(scan_xss(url))
    tasks.append(xss_scan_task)

    # Directory brute-force scan
    dir_scan_task = asyncio.create_task(scan_directory_traversal(url))
    tasks.append(dir_scan_task)

    # SQLMap or Burp scan
    if use_burp:
        vuln_scan_task = asyncio.create_task(vulnerability_scan_burp(url))
    else:
        vuln_scan_task = asyncio.create_task(vulnerability_scan_sqlmap(url))
    tasks.append(vuln_scan_task)

    # Stealth network scan (independent)
    stealth_scan_task = asyncio.create_task(stealth_network_scan())
    tasks.append(stealth_scan_task)

    # Await initial concurrent tasks
    initial_results = await asyncio.gather(*tasks, return_exceptions=True)

    # Assign results to report_data
    result_index = 0
    if open_ports_task:
        open_ports_results = initial_results[result_index]
        report_data["Open Ports"] = open_ports_results
        result_index += 1
    else:
        report_data["Open Ports"] = ["Skipped due to no resolved IP."]

    report_data["Security Header Analysis"] = initial_results[result_index]
    result_index += 1

    report_data["XSS Scan Findings"] = initial_results[result_index]
    result_index += 1

    report_data["Directory & File Discovery"] = initial_results[result_index]
    result_index += 1

    report_data["Vulnerability Scan"] = initial_results[result_index]
    result_index += 1
    
    report_data["Stealth Network Scan Results"] = initial_results[result_index]
    result_index += 1

    # --- Deeper Scan based on user choice and initial results ---
    db_access_results = ["Database access attempt skipped."]
    if proceed_db_scan and resolved_ip:
        extracted_open_ports = []
        for detail in open_ports_results:
            match = re.search(r"Port (\d+)/tcp is OPEN", detail)
            if match:
                extracted_open_ports.append(int(match.group(1)))
        
        # Only attempt DB scan if relevant ports are open
        if any(port in [3306, 5432, 1433] for port in extracted_open_ports):
            db_access_results = await check_for_database_access(resolved_ip, open_ports_results)
        else:
            db_access_results = ["No common database ports found open. Skipping deeper database access attempts."]

    report_data["Database Access Attempts"] = db_access_results

    # --- Comprehensive Web Crawl and Sensitive Data Scan ---
    crawled_pages_data = []
    sensitive_data_findings = []
    discovered_urls_list = []

    if do_comprehensive_crawl:
        crawled_pages_data = await comprehensive_web_crawler(url, max_pages=50, max_depth=2) # Adjust limits as needed
        
        if crawled_pages_data:
            print("[~] Scanning crawled content for sensitive data...")
            for page in crawled_pages_data:
                discovered_urls_list.append(page["url"]) # Collect URLs for reporting
                if "content" in page and isinstance(page["content"], str) and page["content"].strip() != "":
                    page_sensitive_data = scan_for_sensitive_data(page["content"])
                    if page_sensitive_data:
                        sensitive_data_findings.append(f"From URL: {page['url']}")
                        sensitive_data_findings.extend([f"    - {f}" for f in page_sensitive_data])
            if not sensitive_data_findings:
                sensitive_data_findings.append("No sensitive data patterns found in crawled pages (basic check).")
            print("[+] Sensitive data scan on crawled content complete.")
        else:
            discovered_urls_list.append("No pages crawled.")
            sensitive_data_findings.append("No content crawled to scan for sensitive data.")

    report_data["Discovered URLs (Crawl)"] = discovered_urls_list
    report_data["Sensitive Data Findings (Crawl)"] = sensitive_data_findings


    report = ReportGenerator()
    report.generate(report_data)
    print("[+] PDF report generated: CyberSweep_Report.pdf")

def cli_mode():
    print(BANNER)
    url = input("Enter target URL (e.g. http://example.com): ").strip()
    if not is_valid_url(url):
        print("[-] Error: Invalid URL format. Please include http:// or https:// and a valid domain.")
        return
    
    use_burp = input("Use Burp Suite for vulnerability scan? (y/n): ").strip().lower() == "y"
    
    proceed_db_scan = False
    confirm_db = input("Perform deeper database access attempts (WARNING: Potentially intrusive)? (y/n): ").strip().lower()
    if confirm_db == 'y':
        proceed_db_scan = True

    do_comprehensive_crawl = False
    confirm_crawl = input("Perform comprehensive web crawl and sensitive data scan (Recommended for full data access attempt)? (y/n): ").strip().lower()
    if confirm_crawl == 'y':
        do_comprehensive_crawl = True

    asyncio.run(run_scanner(url, use_burp, proceed_db_scan, do_comprehensive_crawl))

def gui_mode():
    class ScannerApp(QWidget):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("CyberSweep GUI")
            self.setGeometry(100, 100, 700, 500) # Increased size
            layout = QVBoxLayout()

            self.url_input = QLineEdit(self)
            self.url_input.setPlaceholderText("Enter target URL")
            layout.addWidget(self.url_input)

            self.burp_checkbox = QCheckBox("Use Burp Suite for vulnerability scan")
            layout.addWidget(self.burp_checkbox)

            self.db_scan_checkbox = QCheckBox("Perform deeper database access attempts (WARNING: Potentially intrusive)")
            layout.addWidget(self.db_scan_checkbox)

            self.crawl_checkbox = QCheckBox("Perform comprehensive web crawl and sensitive data scan")
            layout.addWidget(self.crawl_checkbox)

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
                return
            
            use_burp = self.burp_checkbox.isChecked()
            proceed_db_scan = self.db_scan_checkbox.isChecked()
            do_comprehensive_crawl = self.crawl_checkbox.isChecked()

            if proceed_db_scan:
                msg_box = QMessageBox()
                msg_box.setIcon(QMessageBox.Warning)
                msg_box.setText("WARNING: Deeper database access attempts can be intrusive.")
                msg_box.setInformativeText("This may involve trying default credentials. Ensure you have explicit permission from the target owner before proceeding.")
                msg_box.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
                msg_box.setDefaultButton(QMessageBox.Cancel)
                ret = msg_box.exec_()
                if ret == QMessageBox.Cancel:
                    self.output.append("[!] Deeper database scan cancelled by user.\n")
                    return

            if do_comprehensive_crawl:
                msg_box = QMessageBox()
                msg_box.setIcon(QMessageBox.Information)
                msg_box.setText("Comprehensive Web Crawl & Sensitive Data Scan.")
                msg_box.setInformativeText("This will crawl many pages and analyze their content for sensitive patterns. Ensure you have permission and are aware of the resource usage.")
                msg_box.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
                msg_box.setDefaultButton(QMessageBox.Cancel)
                ret = msg_box.exec_()
                if ret == QMessageBox.Cancel:
                    self.output.append("[!] Comprehensive web crawl cancelled by user.\n")
                    return

            self.output.append(f"[~] Starting scan on {url}\n")
            threading.Thread(target=lambda: asyncio.run(self.scan(url, use_burp, proceed_db_scan, do_comprehensive_crawl)), daemon=True).start()

        async def scan(self, url, use_burp, proceed_db_scan, do_comprehensive_crawl):
            original_stdout = sys.stdout
            sys.stdout = self
            try:
                await run_scanner(url, use_burp, proceed_db_scan, do_comprehensive_crawl)
            finally:
                sys.stdout = original_stdout

        def write(self, msg):
            self.output.append(msg)
            self.output.verticalScrollBar().setValue(self.output.verticalScrollBar().maximum())

        def flush(self):
            pass

    app = QApplication(sys.argv)
    win = ScannerApp()
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    import re # Ensure re is imported for sensitive data scan

    if "--gui" in sys.argv:
        gui_mode()
    else:
        cli_mode()