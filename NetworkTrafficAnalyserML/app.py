from flask import Flask, jsonify, render_template, send_from_directory
from scapy.all import sniff, IP, TCP
import os
from threading import Thread
from flask import request
import re
import time
from scapy.all import Raw
from api.upload import upload_bp
from api.alerts import alerts_bp
from collections import defaultdict
from traffic.analyse import analyze_flow
from ml.inference import predict_flow
from traffic.analyse import scorer
import uuid
import requests
import threading
import time
from functools import wraps
ALERT_THRESHOLD = 5.0         
BLOCK_THRESHOLD = 10.0

flows = defaultdict(list)

app = Flask(__name__, static_folder='static', template_folder='templates')
blocked_ips = set()
captured_packets = []
monitoring = True

proto_map = {0: "HOPOPT", 1: "ICMP", 2: "IGMP", 3: "GGP", 4: "IPv4", 5: "ST", 6: "TCP", 7: "CBT", 8: "EGP", 9: "IGP", 10: "BBN-RCC-MON", 11: "NVP-II", 12: "PUP", 13: "ARGUS (deprecated)", 14: "EMCON", 15: "XNET", 16: "CHAOS", 17: "UDP", 18: "MUX", 19: "DCN-MEAS", 20: "HMP", 21: "PRM", 22: "XNS-IDP", 23: "TRUNK-1", 24: "TRUNK-2", 
             25: "LEAF-1", 26: "LEAF-2", 27: "RDP", 28: "IRTP", 29: "ISO-TP4", 30: "NETBLT", 31: "MFE-NSP", 32: "MERIT-INP", 33: "DCCP", 34: "3PC", 35: "IDPR", 36: "XTP", 37: "DDP", 38: "IDPR-CMTP", 39: "TP++", 40: "IL", 41: "IPv6", 42: "SDRP", 43: "IPv6-Route", 44: "IPv6-Frag", 45: "IDRP", 46: "RSVP", 47: "GRE", 48: "DSR", 
             49: "BNA", 50: "ESP", 51: "AH", 52: "I-NLSP", 53: "SWIPE (deprecated)", 54: "NARP", 55: "Min-IPv4", 56: "TLSP", 57: "SKIP", 58: "IPv6-ICMP", 59: "IPv6-NoNxt", 60: "IPv6-Opts", 61: "any host internal protocol", 62: "CFTP", 63: "any local network", 64: "SAT-EXPAK", 65: "KRYPTOLAN", 66: "RVD", 67: "IPPC", 
             68: "any distributed file system", 69: "SAT-MON", 70: "VISA", 71: "IPCV", 72: "CPNX", 73: "CPHB", 74: "WSN", 75: "PVP", 76: "BR-SAT-MON", 77: "SUN-ND", 78: "WB-MON", 79: "WB-EXPAK", 80: "ISO-IP", 81: "VMTP", 82: "SECURE-VMTP", 83: "VINES", 84: "IPTM", 85: "NSFNET-IGP", 86: "DGP", 87: "TCF", 88: "EIGRP", 89: "OSPFIGP", 
             90: "Sprite-RPC", 91: "LARP", 92: "MTP", 93: "AX.25", 94: "IPIP", 95: "MICP (deprecated)", 96: "SCC-SP", 97: "ETHERIP", 98: "ENCAP", 99: "any private encryption scheme", 100: "GMTP", 101: "IFMP", 102: "PNNI", 103: "PIM", 104: "ARIS", 105: "SCPS", 106: "QNX", 107: "A/N", 108: "IPComp", 109: "SNP", 110: "Compaq-Peer",
             111: "IPX-in-IP", 112: "VRRP", 113: "PGM", 114: "any 0-hop protocol", 115: "L2TP", 116: "DDX", 117: "IATP", 118: "STP", 119: "SRP", 120: "UTI", 121: "SMP", 122: "SM (deprecated)", 123: "PTP", 124: "ISIS over IPv4", 125: "FIRE", 126: "CRTP", 127: "CRUDP", 128: "SSCOPMCE", 129: "IPLT", 130: "SPS", 131: "PIPE", 132: "SCTP", 
             133: "FC", 134: "RSVP-E2E-IGNORE", 135: "Mobility Header", 136: "UDPLite", 137: "MPLS-in-IP", 138: "manet", 139: "HIP", 140: "Shim6", 141: "WESP", 142: "ROHC", 143: "Ethernet", 144: "AGGFRAG", 145: "NSH", 146: "Homa", 147: "BIT-EMU", 148: "Unassigned", 149: "Unassigned", 150: "Unassigned", 151: "Unassigned", 152: "Unassigned", 
             153: "Unassigned", 154: "Unassigned", 155: "Unassigned", 156: "Unassigned", 157: "Unassigned", 158: "Unassigned", 159: "Unassigned", 160: "Unassigned", 161: "Unassigned", 162: "Unassigned", 163: "Unassigned", 164: "Unassigned", 165: "Unassigned", 166: "Unassigned", 167: "Unassigned", 168: "Unassigned", 169: "Unassigned", 170: "Unassigned", 
             171: "Unassigned", 172: "Unassigned", 173: "Unassigned", 174: "Unassigned", 175: "Unassigned", 176: "Unassigned", 177: "Unassigned", 178: "Unassigned", 179: "Unassigned", 180: "Unassigned", 181: "Unassigned", 182: "Unassigned", 183: "Unassigned", 184: "Unassigned", 185: "Unassigned", 186: "Unassigned", 187: "Unassigned", 188: "Unassigned", 
             189: "Unassigned", 190: "Unassigned", 191: "Unassigned", 192: "Unassigned", 193: "Unassigned", 194: "Unassigned", 195: "Unassigned", 196: "Unassigned", 197: "Unassigned", 198: "Unassigned", 199: "Unassigned", 200: "Unassigned", 201: "Unassigned", 202: "Unassigned", 203: "Unassigned", 204: "Unassigned", 205: "Unassigned", 206: "Unassigned", 
             207: "Unassigned", 208: "Unassigned", 209: "Unassigned", 210: "Unassigned", 211: "Unassigned", 212: "Unassigned", 213: "Unassigned", 214: "Unassigned", 215: "Unassigned", 216: "Unassigned", 217: "Unassigned", 218: "Unassigned", 219: "Unassigned", 220: "Unassigned", 221: "Unassigned", 222: "Unassigned", 223: "Unassigned", 224: "Unassigned", 
             225: "Unassigned", 226: "Unassigned", 227: "Unassigned", 228: "Unassigned", 229: "Unassigned", 230: "Unassigned", 231: "Unassigned", 232: "Unassigned", 233: "Unassigned", 234: "Unassigned", 235: "Unassigned", 236: "Unassigned", 237: "Unassigned", 238: "Unassigned", 239: "Unassigned", 240: "Unassigned", 241: "Unassigned", 242: "Unassigned", 
             243: "Unassigned", 244: "Unassigned", 245: "Unassigned", 246: "Unassigned", 247: "Unassigned", 248: "Unassigned", 249: "Unassigned", 250: "Unassigned", 251: "Unassigned", 252: "Unassigned", 253: "Use for experimentation and testing", 254: "Use for experimentation and testing", 255: "Reserved"}


total_packets = 0
blocked_signatures = []

def matches_blocked_signature(payload):
    for pattern in blocked_signatures:
        if re.search(pattern, payload):
            return True
    return False

@app.route('/api/pause_monitoring', methods=['POST'])
def pause_monitoring():
    global monitoring
    monitoring = False
    return jsonify({'status': 'paused'})

@app.route('/api/start_monitoring', methods=['POST'])
def start_monitoring():
    global monitoring
    monitoring = True
    return jsonify({'status': 'started'})

def packet_callback(packet):
    global total_packets, monitoring, blocked_ips
    if not monitoring or IP not in packet:
        return
    
        # Debug: print any TCP packet to port 22
    if packet.haslayer(TCP) and packet[TCP].dport == 22:
        print(f"🔍 DEBUG: captured SYN from {packet[IP].src} to port 22")

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if src_ip in blocked_ips or dst_ip in blocked_ips:
        return

    proto_num = packet.proto
    proto_name = proto_map.get(proto_num, f"Unknown ({proto_num})")

    src_port = dst_port = None
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer("UDP"):
        src_port = packet["UDP"].sport
        dst_port = packet["UDP"].dport

    payload = ""
    if packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode("utf-8", errors="ignore")
            if len(payload) > 500:
                payload = payload[:500] + "..."
        except Exception:
            payload = str(packet[Raw].load)[:500]

    if matches_blocked_signature(payload):
        return

    total_packets += 1
    captured_packets.append({
        "id": str(uuid.uuid4()),
        "src": src_ip,
        "dst": dst_ip,
        "proto": proto_name,
        "src_port": src_port,
        "dst_port": dst_port,
        "time": time.strftime('%H:%M:%S'),
         "timestamp": time.time() * 1000,
        "payload": payload,
        "size": len(packet),     
        "ml_label": "pending",
        "confidence": 0.0,
        "host_score": 0.0,
        "status": "pending"
    })

    '''flow_id = tuple(sorted([
        (src_ip, src_port),
        (dst_ip, dst_port)
    ])) + (proto_name,)'''
    flow_id = (src_ip, dst_ip, dst_port, proto_name)
    flows[flow_id].append(packet)

    if len(flows[flow_id]) >= 20:
        result = analyze_flow(flows[flow_id])
        flows.pop(flow_id, None)



@app.route("/api/block_signatures", methods=["POST"])
def block_signatures():
    global blocked_signatures
    data = request.get_json()
    blocked_signatures = data.get("patterns", [])
    return jsonify({"status": "ok", "blocked_signatures": blocked_signatures})

@app.route("/api/unblock_signatures", methods=["POST"])
def unblock_signatures():
    global blocked_signatures
    blocked_signatures.clear()
    return jsonify({"status": "ok", "cleared": True})

@app.route("/api/block_ips", methods=["POST"])
def block_ips():
    global blocked_ips
    data = request.get_json()
    ips = data.get("ips", [])
    blocked_ips.update(ips)
    return jsonify({"blocked": list(blocked_ips)})

@app.route("/api/unblock_ips", methods=["POST"])
def unblock_ips():
    global blocked_ips
    data = request.get_json()
    ips = data.get("ips", [])
    blocked_ips.difference_update(ips)
    return jsonify({"blocked": list(blocked_ips)})

def start_sniffer():
    sniff(iface="en0", filter="ip", prn=packet_callback, store=False)

@app.route("/")
def index():
    return render_template("NetworkTrafficAnalyser.html")

@app.route("/api/packets")
def get_packets():
    return jsonify(captured_packets)

@app.route("/api/packet_count")
def get_packet_count():
    return jsonify({"total": total_packets})

@app.route('/api/reset', methods=['POST'])
def reset_packets():
    global captured_packets, total_packets
    captured_packets = []
    total_packets = 0
    return jsonify({"status": "reset"}), 200

def decay_worker():
    while True:
        time.sleep(30)
        scorer.decay_all()

# Start background decay thread (daemon so it exits with the app)
threading.Thread(target=decay_worker, daemon=True).start()

import requests
import threading
import time

TOR_EXIT_NODES = set()
TOR_UPDATE_INTERVAL = 3600  # 1 hour

def fetch_tor_exit_nodes():
    global TOR_EXIT_NODES
    urls = [
        "https://check.torproject.org/torbulkexitlist",
        "http://check.torproject.org/torbulkexitlist",   # fallback HTTP
        # Optional: add a mirror if needed
    ]
    for url in urls:
        try:
            resp = requests.get(url, timeout=10, verify=False)  
            if resp.status_code == 200:
                ips = resp.text.strip().split('\n')
                TOR_EXIT_NODES = set(ip for ip in ips if ip)
                print(f"✅ Updated Tor exit nodes from {url}: {len(TOR_EXIT_NODES)} IPs")
                return
        except Exception as e:
            print(f"⚠️ Failed to fetch from {url}: {e}")
            continue
    
    if not TOR_EXIT_NODES:
        fallback_ips = [
            "51.15.252.184",   
            "51.15.214.244",
        ]
        TOR_EXIT_NODES = set(fallback_ips)
        print(f"⚠️ Using fallback Tor exit nodes: {len(TOR_EXIT_NODES)} IPs")

def tor_updater():
    while True:
        fetch_tor_exit_nodes()
        time.sleep(TOR_UPDATE_INTERVAL)

threading.Thread(target=tor_updater, daemon=True).start()

@app.route('/api/tor_exit_nodes', methods=['GET'])
def get_tor_exit_nodes():
    return jsonify(list(TOR_EXIT_NODES))

@app.route("/api/hosts")
def get_hosts():
    hosts_view = {}
    
    snapshot_data = scorer.snapshot()
    
    for host_ip, data in snapshot_data.items():
        
        current_data = scorer.hosts[host_ip]
        
        score = current_data["score"]
        
        if score >= BLOCK_THRESHOLD:
            status = "BLOCK"
        elif score >= ALERT_THRESHOLD:
            status = "ALERT"
        else:
            status = "OK"
        
        hosts_view[host_ip] = {
            "host": host_ip,
            "score": round(score, 2),
            "status": status,
            "label": current_data.get("label", "UNKNOWN"),
            "confidence": round(current_data.get("confidence", 0.0), 4),
            "benign_prob": round(current_data.get("benign_prob", 0.0), 4),
            "malicious_prob": round(current_data.get("malicious_prob", 0.0), 4),
            "last_update": int(current_data.get("last_update", time.time()))
        }
    
    return jsonify(hosts_view)

geo_cache = {}
CACHE_TTL = 3600

import geoip2.database
import os

GEOIP_READER = geoip2.database.Reader(os.path.join('data', 'GeoLite2-City.mmdb'))

@app.route('/api/geo/<ip>')
def get_geo(ip):
    if ip in geo_cache:
        cached = geo_cache[ip]
        if time.time() - cached['timestamp'] < CACHE_TTL:
            return jsonify(cached['data'])
        else:
            del geo_cache[ip]

    octets = ip.split('.')
    if len(octets) == 4:
        first = int(octets[0])
        if ip.startswith('192.168.') or ip.startswith('10.') or (first == 172 and 16 <= int(octets[1]) <= 31) or ip == '127.0.0.1':
            result = {'country_code': 'LOC', 'country_name': 'Local Network', 'city': 'Local', 'latitude': None, 'longitude': None}
            geo_cache[ip] = {'timestamp': time.time(), 'data': result}
            return jsonify(result)

    try:
        response = GEOIP_READER.city(ip)
        result = {
            'country_code': response.country.iso_code or 'UNK',
            'country_name': response.country.name or 'Unknown',
            'city': response.city.name or response.country.name or 'Unknown',
            'latitude': response.location.latitude,
            'longitude': response.location.longitude
        }
        geo_cache[ip] = {'timestamp': time.time(), 'data': result}
        return jsonify(result)
    except Exception:
        result = {'country_code': 'UNK', 'country_name': 'Unknown', 'city': 'Unknown', 'latitude': None, 'longitude': None}
        geo_cache[ip] = {'timestamp': time.time(), 'data': result}
        return jsonify(result)
    
ip_enrichment_cache = {}
ENRICHMENT_CACHE_TTL = 3600 

def get_ip_enrichment(ip):
    if ip in ip_enrichment_cache:
        cached = ip_enrichment_cache[ip]
        if time.time() - cached['timestamp'] < ENRICHMENT_CACHE_TTL:
            return cached['data']

    if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('127.') or \
       (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31):
        result = {
            'isp': 'Local Network',
            'org': 'Local Network',
            'asn': None
        }
        ip_enrichment_cache[ip] = {'timestamp': time.time(), 'data': result}
        return result

    try:
        url = f'http://ip-api.com/json/{ip}?fields=status,message,isp,org,as'
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get('status') == 'success':
                result = {
                    'isp': data.get('isp', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'asn': data.get('as', 'Unknown')
                }
                ip_enrichment_cache[ip] = {'timestamp': time.time(), 'data': result}
                return result
            else:
                print(f"ip-api error for {ip}: {data.get('message', 'unknown error')}")
        else:
            print(f"ip-api HTTP error {resp.status_code} for {ip}")
    except Exception as e:
        print(f"ip-api exception for {ip}: {e}")

    result = {'isp': 'Unknown', 'org': 'Unknown', 'asn': 'Unknown'}
    ip_enrichment_cache[ip] = {'timestamp': time.time(), 'data': result}
    return result

ABUSEIPDB_KEY = None  

def check_abuseipdb(ip):
    if not ABUSEIPDB_KEY:
        return None
    try:
        headers = {'Key': ABUSEIPDB_KEY, 'Accept': 'application/json'}
        url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90'
        resp = requests.get(url, headers=headers, timeout=5)
        if resp.status_code == 200:
            data = resp.json().get('data', {})
            return {
                'abuse_score': data.get('abuseConfidenceScore', 0),
                'categories': data.get('categories', []),
                'reputation': 'malicious' if data.get('abuseConfidenceScore', 0) > 50 else 'suspicious' if data.get('abuseConfidenceScore', 0) > 20 else 'clean'
            }
    except Exception as e:
        print(f"AbuseIPDB error for {ip}: {e}")
    return None

@app.route('/api/ip_info/<ip>')
def ip_info(ip):
    parts = ip.split('.')
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return jsonify({'error': 'Invalid IP address'}), 400

    geo_result = None
    if ip in geo_cache:
        cached = geo_cache[ip]
        if time.time() - cached['timestamp'] < CACHE_TTL:
            geo_result = cached['data']
        else:
            del geo_cache[ip]
    if not geo_result:
        if ip.startswith('192.168.') or ip.startswith('10.') or \
           (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31) or \
           ip == '127.0.0.1':
            geo_result = {'country_code': 'LOC', 'country_name': 'Local Network', 'city': 'Local', 'latitude': None, 'longitude': None}
        else:
            try:
                response = GEOIP_READER.city(ip)
                geo_result = {
                    'country_code': response.country.iso_code or 'UNK',
                    'country_name': response.country.name or 'Unknown',
                    'city': response.city.name or response.country.name or 'Unknown',
                    'latitude': response.location.latitude,
                    'longitude': response.location.longitude
                }
            except Exception:
                geo_result = {'country_code': 'UNK', 'country_name': 'Unknown', 'city': 'Unknown', 'latitude': None, 'longitude': None}
        geo_cache[ip] = {'timestamp': time.time(), 'data': geo_result}

    enrichment = get_ip_enrichment(ip)

    is_tor = ip in TOR_EXIT_NODES

    abuse = check_abuseipdb(ip) if ABUSEIPDB_KEY else None

    result = {
        'ip': ip,
        'country_code': geo_result.get('country_code', 'UNK'),
        'country': geo_result.get('country_name', 'Unknown'),
        'city': geo_result.get('city', 'Unknown'),
        'latitude': geo_result.get('latitude'),
        'longitude': geo_result.get('longitude'),
        'isp': enrichment.get('isp', 'Unknown'),
        'org': enrichment.get('org', 'Unknown'),
        'asn': enrichment.get('asn', 'Unknown'),
        'tor': is_tor
    }
    if abuse:
        result['reputation'] = abuse.get('reputation', 'unknown')
        result['abuse_score'] = abuse.get('abuse_score', 0)
        result['abuse_categories'] = abuse.get('categories', [])
    else:
        result['reputation'] = 'unknown'
        result['abuse_score'] = None
        result['abuse_categories'] = []

    return jsonify(result)
    
app.register_blueprint(upload_bp)
app.register_blueprint(alerts_bp)

if __name__ == "__main__":
    Thread(target=start_sniffer, daemon=True).start()
    app.run(debug=True)
