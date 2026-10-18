# traffic/analyse.py
from ml.inference import predict_flow
from ml.host_scoring import HostScorer
from scapy.all import IP

scorer = HostScorer()

def analyze_flow(flow):
    prediction = predict_flow(flow)
    
    # Extract IP address
    host_ip = None
    for packet in flow:
        if hasattr(packet, 'haslayer') and packet.haslayer('IP'):
            host_ip = packet['IP'].src
            break
    
    if host_ip is None:
        host_ip = flow[0].src if flow else "UNKNOWN"
    
    mal_prob = prediction["malicious_prob"]

    '''print(f"📊 Storing for {host_ip}:")
    print(f"   label={prediction['label']}")
    print(f"   confidence={prediction['confidence']}")
    print(f"   benign_prob={prediction['benign_prob']}")
    print(f"   malicious_prob={mal_prob}")'''

    status, score = scorer.update(
        host_ip, 
        mal_prob,
        label=prediction["label"],
        confidence=prediction["confidence"],
        benign_prob=prediction["benign_prob"],
        malicious_prob_raw=mal_prob
    )

    '''stored = scorer.hosts.get(host_ip, {})
    print(f"✅ After storage: label={stored.get('label')}, confidence={stored.get('confidence')}")
    
    if status == "ALERT":
        print(f"[ALERT] {host_ip} score={score:.2f}")
    elif status == "BLOCK":
        print(f"[BLOCK] {host_ip} score={score:.2f}")'''
    
    return {
        "host": host_ip,
        "status": status,
        "score": score,
        **prediction
    }