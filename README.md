# CyberScan Elite v2.0 — Full Setup Guide

## 📁 Folder Structure

```
cyberscan-elite-v2/
├── app.py                  ← Flask backend (all logic here)
├── requirements.txt        ← Python dependencies
├── scans.db                ← Auto-created SQLite database (scan history)
└── templates/
    ├── index.html          ← Landing page
    ├── scan.html           ← Scanner page (main tool)
    └── history.html        ← Scan history page
```

---

## ⚙️ Prerequisites

Install these before running:

1. **Python 3.8+** → https://python.org
2. **Nmap** → https://nmap.org/download.html
   - **Windows:** Download the `.exe` installer from nmap.org
   - **Mac:** `brew install nmap`
   - **Linux/Ubuntu:** `sudo apt install nmap`

---

## 🚀 How to Run in VS Code

### Step 1 — Open the project folder
```
File → Open Folder → select cyberscan-elite-v2
```

### Step 2 — Open terminal in VS Code
```
Terminal → New Terminal    (or Ctrl + `)
```

### Step 3 — Create a virtual environment
```bash
python -m venv venv
```

Activate it:
- **Windows:** `venv\Scripts\activate`
- **Mac/Linux:** `source venv/bin/activate`

### Step 4 — Install dependencies
```bash
pip install -r requirements.txt
```

### Step 5 — Run the server
```bash
python app.py
```

You should see:
```
 * Running on http://127.0.0.1:5000
```

### Step 6 — Open in browser
Go to: **http://localhost:5000**

---

## 🔐 Important — Admin/Root Privileges

Some features **require elevated privileges** to work:

| Feature | Requires Admin/Root? |
|---|---|
| Normal TCP Scan | No |
| Single Port Scan | No |
| Port Range Scan | No |
| OS Detection | ✅ YES |
| UDP Scan | ✅ YES |
| Vulnerability Scan | Sometimes |

**To run with admin:**
- **Windows:** Right-click VS Code → "Run as Administrator", then run `python app.py`
- **Mac/Linux:** `sudo python app.py` or `sudo venv/bin/python app.py`

---

## ✨ New Features in v2.0

| Feature | Description |
|---|---|
| OS Detection | Detects target operating system |
| Vulnerability Scan | NSE scripts find CVEs on open ports |
| UDP Port Scan | Scans top 20 UDP ports |
| GeoIP Lookup | Country, city, ISP of target |
| WHOIS Lookup | Domain registration information |
| Host Discovery | Checks if host is alive before scanning |
| Scan Cancellation | Cancel any running scan mid-way |
| Live Port Feed | Open ports pop up in real-time |
| Scan History | All scans saved to local SQLite DB |
| Downloadable Reports | Full styled HTML report export |
| Risk Descriptions | Each port includes a security description |
| CVE Count per Port | Shows how many CVEs found per open port |

---

## 🛠️ Troubleshooting

| Problem | Fix |
|---|---|
| `nmap not found` | Install nmap and add it to your PATH |
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` |
| OS/UDP scan fails | Run VS Code / terminal as Administrator or sudo |
| Scan hangs | Try a smaller port range first |
| WHOIS not working | Install `whois` tool: `sudo apt install whois` (Linux) |
| GeoIP returns nothing | Check internet connection (uses ip-api.com) |

---

## 📝 Notes

- `scans.db` is created automatically in the project folder on first run
- The GeoIP feature uses the free `ip-api.com` API (no key needed)
- WHOIS requires the `whois` command-line tool on your system
- Vulnerability scans can take significantly longer on many open ports