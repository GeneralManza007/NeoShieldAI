import time
from collections import defaultdict

# Risk score is now 0–100
DECAY_HALF_LIFE = 60          # seconds – score halves in 60s if no new activity
ALERT_THRESHOLD = 50.0        # 50+ = ALERT
BLOCK_THRESHOLD = 80.0        # 80+ = BLOCK
MAX_SCORE = 100.0

class HostScorer:
    def __init__(self):
        self.hosts = defaultdict(lambda: {
            "score": 0.0,
            "last_update": time.time(),
            "status": "OK",
            "label": "UNKNOWN",
            "confidence": 0.0,
            "benign_prob": 0.0,
            "malicious_prob": 0.0
        })

    def _decay(self, host):
        now = time.time()
        elapsed = now - self.hosts[host]["last_update"]

        if elapsed <= 0:
            return
        
        decay_factor = 0.5 ** (elapsed / DECAY_HALF_LIFE)
        self.hosts[host]["score"] *= decay_factor
        self.hosts[host]["last_update"] = now

    def decay_all(self):
        """Apply decay to all tracked hosts (call from background thread)"""
        for host_ip in list(self.hosts.keys()):
            self._decay(host_ip)

    def update(self, host_ip, malicious_prob, label=None, confidence=None, 
               benign_prob=None, malicious_prob_raw=None):
        
        # DO NOT decay here – decay is handled by background thread
        
        host = self.hosts[host_ip]
        
        # Update ML fields
        if label is not None:
            host["label"] = label
        if confidence is not None:
            host["confidence"] = confidence
        if benign_prob is not None:
            host["benign_prob"] = benign_prob
        if malicious_prob_raw is not None:
            host["malicious_prob"] = malicious_prob_raw
        elif malicious_prob is not None:
            host["malicious_prob"] = malicious_prob
        
        # Scale malicious probability to 0–50 points (so one malicious flow can trigger ALERT)
        # You can adjust the multiplier (e.g., 30, 50, 60)
        increment = malicious_prob * 50
        host["score"] += increment
        host["score"] = min(host["score"], MAX_SCORE)
        score = host["score"]
        
        # Update status based on new thresholds
        if score >= BLOCK_THRESHOLD:
            host["status"] = "BLOCK"
            return "BLOCK", score
        elif score >= ALERT_THRESHOLD:
            host["status"] = "ALERT"
            return "ALERT", score
        else:
            host["status"] = "OK"
            return "OK", score
    
    def snapshot(self):
        """Return a copy of the hosts data"""
        snapshot_copy = {}
        for host_ip, data in self.hosts.items():
            snapshot_copy[host_ip] = {
                "host": host_ip,
                "score": data["score"],
                "status": data["status"],
                "label": data["label"],
                "confidence": data["confidence"],
                "benign_prob": data["benign_prob"],
                "malicious_prob": data["malicious_prob"],
                "last_update": data["last_update"]
            }
        return snapshot_copy