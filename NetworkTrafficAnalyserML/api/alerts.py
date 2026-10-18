from flask import Blueprint, jsonify
from ml.inference import predict_flow
from traffic.flows import extract_flows

alerts_bp = Blueprint("alerts", __name__)

@alerts_bp.route("/api/analyze")
def analyze():
    pcap = "uploads/sample.pcap"
    flows = extract_flows(pcap)

    alerts = []
    for fid, packets in flows.items():
        if len(packets) >= 10:
            label = predict_flow(packets)
            if label != "BENIGN":   
                alerts.append({
                    "flow": fid,
                    "attack": label
                })

    return jsonify(alerts)
