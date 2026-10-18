from scapy.all import rdpcap
from collections import defaultdict

def extract_flows(pcap_path):
    packets = rdpcap(pcap_path)
    flows = defaultdict(list)

    for pkt in packets:
        if pkt.haslayer("IP"):
            key = (
                pkt["IP"].src,
                pkt["IP"].dst,
                pkt.sport if pkt.haslayer("TCP") or pkt.haslayer("UDP") else 0,
                pkt.dport if pkt.haslayer("TCP") or pkt.haslayer("UDP") else 0,
                pkt.proto
            )
            flows[key].append(pkt)

    return flows
