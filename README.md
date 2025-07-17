
# 🛡️ CyberSweep - Advanced Web Vulnerability Scanner

CyberSweep is a professional-grade, Python-based **Ethical Hacking and Web Vulnerability Scanning** tool designed for cybersecurity enthusiasts, students, and researchers. It combines the power of industry-standard tools (like `nmap`, `sqlmap`, and `scapy`) with a user-friendly **CLI and optional GUI**, offering a full suite of scanning and analysis capabilities.

> ⚠️ **For ethical and educational use only. Always have authorization before scanning any system.**

---

## 📌 Features

✅ **Subdomain Enumeration**  
✅ **Advanced Port Scanning** (via `nmap` or fallback Python scanner)  
✅ **Stealth Scanning Techniques**  
✅ **HTTP Header Analysis**  
✅ **Login & Session-based SQL Injection Testing** (via `sqlmap`)  
✅ **PDF Report Generation** (auto-generated after every scan)  
✅ **Terminal Logging + GUI Mode (`--gui` flag)**  
✅ **Exception & Fallback Handling** for missing tools  
✅ **Professional Design with ASCII Logo, CLI & GUI Modes**  
✅ **.exe Bundling Support for Offline Submissions**

---

## 🖼️ Screenshots

<p align="center">
  <img src="assets/banner.png" alt="CyberSweep Banner" width="600">
  <img src="assets/gui_sample.png" alt="GUI Screenshot" width="400">
  <img src="assets/report_sample.png" alt="Sample PDF Report" width="400">
</p>

---

## 🚀 How to Use

### 🔧 CLI Mode (Default)

```bash
python main.py
```

### 🖥️ GUI Mode (Optional)

```bash
python main.py --gui
```

### 🧪 Features Menu (CLI)
Once launched, you'll get a menu with the following:
- Subdomain Scanner
- Port Scanner
- Header Fetcher
- SQL Injection Checker (using sqlmap)
- Stealth Scan (using Scapy/Nmap)
- Generate PDF Report

---

## 📄 Output

Every scan automatically generates a professional PDF report with:
- ✅ Scan Timestamp
- 🌐 Target URL & IP
- 🔍 Open Ports
- 📥 HTTP Headers
- ⚠️ Vulnerability Status
- 🕵️‍♂️ Stealth Scan Logs
- 📌 Tool Status Summary

---

## 📁 Directory Structure

```
CyberSweep/
├── main.py                # Main script
├── gui/                   # PyQt5 GUI assets
├── reports/               # Generated PDF reports
├── modules/               # Custom Python modules for scanning
├── assets/                # Logo, icons, banner, etc.
├── requirements.txt       # Required packages
└── README.md              # Project documentation
```

---

## 🔧 Installation

### 📦 Requirements

- Python 3.10+
- `nmap`, `sqlmap`, `scapy` installed (optional, with fallback support)
- Recommended tools:
  ```bash
  pip install -r requirements.txt
  ```

### 🪟 Windows `.exe` Support

To bundle into an executable:
```bash
pyinstaller --onefile --noconsole main.py
```
To download the direct file click on installer.exe
---

## 📘 Example PDF Report

> ✅ A detailed report is auto-generated with each scan inside the `reports/` folder. Perfect for institutional submission.

---

## 🎯 Use Cases

- ✅ Ethical Hacking Training
- ✅ Penetration Testing Simulations
- ✅ Institutional Projects & Demos
- ✅ Security Audits for Devs

---

## ❗ Disclaimers

- **Educational Use Only**  
- Do not use this tool on unauthorized targets.
- The developer is not responsible for any misuse of this tool.

---

## 📬 Contact

Made by [Abhiram Lanka](https://github.com/Abhiram-ops)  
For queries or collaborations, reach out via GitHub or [LinkedIn](https://www.linkedin.com/in/abhiram-lanka/)

---

## 🌟 Star this repo if you found it helpful!
