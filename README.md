# 🛡️ CyberScan Elite — Advanced Port Intelligence System

A professional-grade, web-based network port scanning tool built with 
Python (Flask) and Nmap. Designed for security professionals, developers, 
and system administrators.

## 🚀 Features
- 3 Scan Modes: Normal (Top 20), Single Port, Port Range
- Real-time progress bar via Server-Sent Events (SSE)
- Multi-threaded parallel scanning engine
- OS Detection & Service Version Fingerprinting
- CVE-based Vulnerability Scanning (NSE Scripts)
- GeoIP & WHOIS Intelligence
- UDP Port Scanning
- Scan History with SQLite persistence
- Downloadable HTML Reports
- Risk Classification (HIGH / MEDIUM / LOW)

## 🛠️ Tech Stack
| Layer | Technology |
|---|---|
| Backend | Python, Flask |
| Scanning Engine | Nmap (python-nmap) |
| Frontend | HTML5, CSS3, JavaScript |
| Database | SQLite3 |
| Real-time | Server-Sent Events (SSE) |

## ⚙️ How to Run
1. Install Nmap → https://nmap.org/download.html
2. Clone this repo
3. Create virtual environment: `python -m venv venv`
4. Activate: `venv\Scripts\activate` (Windows)
5. Install dependencies: `pip install -r requirements.txt`
6. Run: `python app.py`
7. Open browser: `http://localhost:5000`

## 📸 Screenshots
*(Add screenshots of your landing page and scan results here)*

## ⚠️ Disclaimer
For authorized use only. Only scan systems you own or have permission to test.
