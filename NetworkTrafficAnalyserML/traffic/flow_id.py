from scapy.all import IP, TCP, UDP

def get_flow_id(pkt):
    if not pkt.haslayer(IP):
        return None

    proto = pkt.proto
    src = pkt[IP].src
    dst = pkt[IP].dst

    sport = dport = 0
    if pkt.haslayer(TCP):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport

    return (src, dst, sport, dport, proto)
