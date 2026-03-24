from flask import Flask, render_template, request, jsonify, Response, stream_with_context, session
import nmap
import json
import time
import threading
import socket
import requests
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import queue
import uuid
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'cyberscan-elite-secret-2024'

# ─── DATABASE SETUP ───────────────────────────────────────────────────────────
DB_PATH = 'scans.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id TEXT PRIMARY KEY,
            target TEXT,
            scan_type TEXT,
            timestamp TEXT,
            duration REAL,
            total_scanned INTEGER,
            open_count INTEGER,
            report_json TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# ─── GLOBAL SCAN SESSIONS ─────────────────────────────────────────────────────
scan_sessions = {}
active_scans = {}  # for cancellation

# ─── HELPERS ──────────────────────────────────────────────────────────────────
def get_risk_level(port):
    high_risk   = [21,22,23,25,135,139,445,1433,3306,3389,5900,23,512,513,514]
    medium_risk = [53,80,110,143,443,993,995,8080,8443,8888,9090,2222]
    if port in high_risk:   return 'HIGH'
    if port in medium_risk: return 'MEDIUM'
    return 'LOW'

def get_risk_description(port, service):
    descriptions = {
        21:   'FTP allows unencrypted file transfer. Risk of credential sniffing.',
        22:   'SSH open to internet. Risk of brute-force attacks.',
        23:   'Telnet is unencrypted. Highly insecure — should be disabled.',
        25:   'SMTP may allow open relay or email spoofing.',
        80:   'HTTP serves unencrypted web traffic.',
        135:  'MS-RPC is a common attack vector on Windows systems.',
        139:  'NetBIOS can expose Windows file shares.',
        443:  'HTTPS — check SSL/TLS certificate validity.',
        445:  'SMB is frequently targeted by ransomware (EternalBlue).',
        1433: 'MSSQL database exposed. Risk of SQL injection or brute-force.',
        3306: 'MySQL database exposed. Should not be publicly accessible.',
        3389: 'RDP exposed — high risk of brute-force and ransomware entry.',
        5900: 'VNC remote desktop — often lacks encryption.',
        8080: 'Alternative HTTP port — may expose dev/admin interfaces.',
    }
    return descriptions.get(port, f'Service "{service}" detected on this port.')

def whois_lookup(target):
    try:
        result = subprocess.run(['whois', target], capture_output=True, text=True, timeout=10)
        lines = result.stdout.strip().split('\n')
        info = {}
        for line in lines:
            if ':' in line:
                key, _, val = line.partition(':')
                key = key.strip().lower()
                val = val.strip()
                if val and key in ['registrar','creation date','expiry date','updated date',
                                   'registrant country','name server','domain name']:
                    info[key] = val
        return info
    except:
        return {}

def geoip_lookup(target):
    try:
        # resolve domain to IP first
        ip = socket.gethostbyname(target)
        r = requests.get(f'http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,lat,lon', timeout=5)
        data = r.json()
        if data.get('status') == 'success':
            return {
                'ip': ip,
                'country': data.get('country','—'),
                'region': data.get('regionName','—'),
                'city': data.get('city','—'),
                'isp': data.get('isp','—'),
                'org': data.get('org','—'),
                'lat': data.get('lat'),
                'lon': data.get('lon'),
            }
        return {'ip': ip}
    except Exception as e:
        return {'ip': target, 'error': str(e)}

def host_discovery(target):
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments='-sn')
        hosts = nm.all_hosts()
        if hosts:
            host = hosts[0]
            state = nm[host].state()
            return {'alive': state == 'up', 'hostname': nm[host].hostname()}
        return {'alive': False}
    except:
        return {'alive': True}  # assume alive if ping blocked

def run_vuln_scan(target, ports_str):
    """Run nmap NSE vuln scripts on open ports."""
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, ports=ports_str, arguments='--script vuln -T4', timeout=120)
        vulns = {}
        for host in nm.all_hosts():
            if 'tcp' in nm[host]:
                for port, data in nm[host]['tcp'].items():
                    scripts = data.get('script', {})
                    if scripts:
                        vulns[port] = []
                        for script_name, output in scripts.items():
                            if 'vuln' in script_name.lower() or 'CVE' in output:
                                cves = re.findall(r'CVE-\d{4}-\d+', output)
                                vulns[port].append({
                                    'script': script_name,
                                    'output': output[:500],
                                    'cves': cves
                                })
        return vulns
    except:
        return {}

# ─── MAIN SCAN RUNNER ─────────────────────────────────────────────────────────
def run_scan(session_id, target, scan_type, port=None, port_range=None,
             run_vuln=False, run_os=False, run_udp=False):
    session = scan_sessions[session_id]
    q = session['queue']
    active_scans[session_id] = True

    try:
        q.put({'type':'status','message':f'Resolving target: {target}','progress':1})

        # ── Host Discovery
        q.put({'type':'status','message':'Checking if host is alive...','progress':2})
        host_info = host_discovery(target)
        if not host_info.get('alive', True):
            q.put({'type':'status','message':'Host appears down — attempting scan anyway...','progress':3})

        # ── GeoIP
        q.put({'type':'status','message':'Fetching GeoIP information...','progress':4})
        geo = geoip_lookup(target)

        # ── WHOIS
        q.put({'type':'status','message':'Running WHOIS lookup...','progress':5})
        whois = whois_lookup(target)

        # ── Determine ports
        if scan_type == 'normal':
            ports_to_scan = [21,22,23,25,53,80,110,111,135,139,
                             143,443,445,993,995,1723,3306,3389,5900,8080]
            scan_label = 'Top 20 Common Ports'
        elif scan_type == 'single':
            ports_to_scan = [int(port)]
            scan_label = f'Single Port {port}'
        elif scan_type == 'range':
            s, e = int(port_range['start']), int(port_range['end'])
            ports_to_scan = list(range(s, e+1))
            scan_label = f'Port Range {s}–{e}'

        total = len(ports_to_scan)
        q.put({'type':'status','message':f'Starting TCP scan: {scan_label} ({total} ports)','progress':6})

        results = {}
        open_ports_live = []
        completed = 0

        max_workers = min(50, max(5, total // 10))
        chunk_size  = max(1, min(100, total // max_workers + 1))
        chunks = [ports_to_scan[i:i+chunk_size] for i in range(0, total, chunk_size)]

        q.put({'type':'status','message':f'TCP scan — {min(max_workers,len(chunks))} parallel threads active...','progress':8})

        def scan_chunk(chunk_ports):
            if not active_scans.get(session_id, False):
                return {}
            nm_local = nmap.PortScanner()
            port_str = ','.join(map(str, chunk_ports))
            try:
                nm_local.scan(hosts=target, ports=port_str, arguments='-sV --version-intensity 9 -T4')
                chunk_results = {}
                for host in nm_local.all_hosts():
                    if 'tcp' in nm_local[host]:
                        for p, data in nm_local[host]['tcp'].items():
                            chunk_results[p] = {
                                'state':   data.get('state','closed'),
                                'service': data.get('name','unknown'),
                                'version': data.get('version',''),
                                'product': data.get('product',''),
                                'extrainfo': data.get('extrainfo',''),
                            }
                return chunk_results
            except:
                return {}

        with ThreadPoolExecutor(max_workers=min(max_workers, len(chunks))) as executor:
            futures = {executor.submit(scan_chunk, chunk): chunk for chunk in chunks}
            for future in as_completed(futures):
                if not active_scans.get(session_id, False):
                    q.put({'type':'cancelled','message':'Scan cancelled by user.'})
                    return
                chunk = futures[future]
                try:
                    cr = future.result()
                    results.update(cr)
                    newly_open = []
                    for p, data in cr.items():
                        if data['state'] == 'open':
                            open_ports_live.append(p)
                            newly_open.append({
                                'port': p,
                                'service': data['service'],
                                'version': data.get('version',''),
                                'product': data.get('product',''),
                            })
                    if newly_open:
                        q.put({'type':'port_found','ports': newly_open})
                except:
                    pass

                completed += len(chunk)
                progress = 8 + int((completed / total) * 55)
                q.put({
                    'type':'progress','progress': min(progress,63),
                    'scanned': completed,'total': total,
                    'open_found': len(open_ports_live),
                    'message': f'TCP scan: {completed}/{total} ports — {len(open_ports_live)} open'
                })

        # ── UDP Scan (top 20 UDP ports)
        udp_results = {}
        if run_udp:
            q.put({'type':'status','message':'Starting UDP scan on top ports...','progress':65})
            try:
                nm_udp = nmap.PortScanner()
                nm_udp.scan(hosts=target, arguments='-sU --top-ports 20 -T4')
                for host in nm_udp.all_hosts():
                    if 'udp' in nm_udp[host]:
                        for p, data in nm_udp[host]['udp'].items():
                            if data.get('state') in ('open','open|filtered'):
                                udp_results[p] = {
                                    'state':   data.get('state'),
                                    'service': data.get('name','unknown'),
                                    'version': data.get('version',''),
                                }
            except:
                pass
            q.put({'type':'status','message':f'UDP scan complete — {len(udp_results)} open/filtered','progress':72})

        # ── OS Detection
        os_info = {}
        if run_os:
            q.put({'type':'status','message':'Running OS detection...','progress':74})
            try:
                nm_os = nmap.PortScanner()
                nm_os.scan(hosts=target, arguments='-O -T4')
                for host in nm_os.all_hosts():
                    osmatch = nm_os[host].get('osmatch', [])
                    if osmatch:
                        best = osmatch[0]
                        os_info = {
                            'name':     best.get('name','Unknown'),
                            'accuracy': best.get('accuracy','—'),
                            'family':   best.get('osclass',[{}])[0].get('osfamily','—') if best.get('osclass') else '—',
                        }
            except:
                os_info = {'name':'Could not detect (requires root/admin)','accuracy':'—','family':'—'}
            q.put({'type':'status','message':f'OS detected: {os_info.get("name","Unknown")}','progress':80})

        # ── Vulnerability Scan
        vuln_results = {}
        if run_vuln and open_ports_live:
            q.put({'type':'status','message':'Running vulnerability scripts on open ports...','progress':82})
            open_str = ','.join(map(str, sorted(open_ports_live)))
            vuln_results = run_vuln_scan(target, open_str)
            total_vulns = sum(len(v) for v in vuln_results.values())
            q.put({'type':'status','message':f'Vulnerability scan complete — {total_vulns} issue(s) found','progress':93})

        # ── Build report
        q.put({'type':'status','message':'Compiling final report...','progress':96})

        open_ports_data = []
        for p in sorted(results.keys()):
            data = results[p]
            if data['state'] == 'open':
                port_vulns = vuln_results.get(p, [])
                open_ports_data.append({
                    'port':        p,
                    'protocol':    'tcp',
                    'state':       data['state'],
                    'service':     data['service'],
                    'version':     data.get('version',''),
                    'product':     data.get('product',''),
                    'extrainfo':   data.get('extrainfo',''),
                    'risk':        get_risk_level(p),
                    'description': get_risk_description(p, data['service']),
                    'vulns':       port_vulns,
                    'cve_count':   sum(len(v.get('cves',[])) for v in port_vulns),
                })

        udp_ports_data = []
        for p, data in udp_results.items():
            udp_ports_data.append({
                'port':    p,
                'protocol':'udp',
                'state':   data['state'],
                'service': data['service'],
                'version': data.get('version',''),
                'risk':    get_risk_level(p),
            })

        duration = round(time.time() - session['start_time'], 2)
        report = {
            'id':            session_id,
            'target':        target,
            'scan_type':     scan_label,
            'timestamp':     datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'duration':      duration,
            'total_scanned': total,
            'open_count':    len(open_ports_data),
            'closed_count':  total - len(open_ports_data),
            'ports':         open_ports_data,
            'udp_ports':     udp_ports_data,
            'os_info':       os_info,
            'geo':           geo,
            'whois':         whois,
            'host_info':     host_info,
            'vuln_enabled':  run_vuln,
            'os_enabled':    run_os,
            'udp_enabled':   run_udp,
            'high_risk_count':   sum(1 for p in open_ports_data if p['risk']=='HIGH'),
            'medium_risk_count': sum(1 for p in open_ports_data if p['risk']=='MEDIUM'),
            'total_cves':        sum(p.get('cve_count',0) for p in open_ports_data),
        }

        # Save to DB
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('''INSERT INTO scan_history VALUES (?,?,?,?,?,?,?,?)''', (
                session_id, target, scan_label,
                report['timestamp'], duration,
                total, len(open_ports_data),
                json.dumps(report)
            ))
            conn.commit()
            conn.close()
        except:
            pass

        session['report'] = report
        q.put({'type':'complete','progress':100,'report':report})

    except Exception as e:
        q.put({'type':'error','message':str(e)})
    finally:
        active_scans.pop(session_id, None)


# ─── ROUTES ───────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan')
def scan_page():
    return render_template('scan.html')

@app.route('/history')
def history_page():
    return render_template('history.html')

@app.route('/api/start-scan', methods=['POST'])
def start_scan():
    data       = request.json
    target     = data.get('target','').strip()
    scan_type  = data.get('scan_type','normal')
    port       = data.get('port')
    port_range = data.get('port_range')
    run_vuln   = data.get('run_vuln', False)
    run_os     = data.get('run_os', False)
    run_udp    = data.get('run_udp', False)

    if not target:
        return jsonify({'error':'Target is required'}), 400

    session_id = str(uuid.uuid4())
    scan_sessions[session_id] = {
        'queue':      queue.Queue(),
        'start_time': time.time(),
        'report':     None,
    }

    thread = threading.Thread(
        target=run_scan,
        args=(session_id, target, scan_type, port, port_range, run_vuln, run_os, run_udp)
    )
    thread.daemon = True
    thread.start()
    return jsonify({'session_id': session_id})

@app.route('/api/cancel-scan/<session_id>', methods=['POST'])
def cancel_scan(session_id):
    active_scans[session_id] = False
    return jsonify({'status':'cancelling'})

@app.route('/api/scan-progress/<session_id>')
def scan_progress(session_id):
    def generate():
        if session_id not in scan_sessions:
            yield f"data: {json.dumps({'type':'error','message':'Session not found'})}\n\n"
            return
        q = scan_sessions[session_id]['queue']
        while True:
            try:
                event = q.get(timeout=60)
                yield f"data: {json.dumps(event)}\n\n"
                if event['type'] in ('complete','error','cancelled'):
                    break
            except queue.Empty:
                yield f"data: {json.dumps({'type':'heartbeat'})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no'}
    )

@app.route('/api/history')
def get_history():
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT id,target,scan_type,timestamp,duration,total_scanned,open_count FROM scan_history ORDER BY timestamp DESC LIMIT 50')
        rows = c.fetchall()
        conn.close()
        history = [{'id':r[0],'target':r[1],'scan_type':r[2],'timestamp':r[3],
                    'duration':r[4],'total_scanned':r[5],'open_count':r[6]} for r in rows]
        return jsonify(history)
    except:
        return jsonify([])

@app.route('/api/history/<scan_id>')
def get_scan_detail(scan_id):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT report_json FROM scan_history WHERE id=?', (scan_id,))
        row = c.fetchone()
        conn.close()
        if row:
            return jsonify(json.loads(row[0]))
        return jsonify({'error':'Not found'}), 404
    except:
        return jsonify({'error':'DB error'}), 500

@app.route('/api/history/<scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('DELETE FROM scan_history WHERE id=?', (scan_id,))
        conn.commit()
        conn.close()
        return jsonify({'status':'deleted'})
    except:
        return jsonify({'error':'DB error'}), 500

@app.route('/api/history/clear', methods=['DELETE'])
def clear_history():
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('DELETE FROM scan_history')
        conn.commit()
        conn.close()
        return jsonify({'status':'cleared'})
    except:
        return jsonify({'error':'DB error'}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000, threaded=True)