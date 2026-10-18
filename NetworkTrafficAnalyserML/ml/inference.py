# ml/inference.py
import torch
from ml.model import TrafficCNN
from traffic.features import encode_flow
from traffic.utils import flow_to_image

device = torch.device("cpu")

model = TrafficCNN()
model.load_state_dict(torch.load("ml/weights.pth", map_location=device))
model.eval()

MALICIOUS_THRESHOLD = 0.90
BENIGN_THRESHOLD = 0.90

def predict_flow(flow):
    features = encode_flow(flow)
    img = flow_to_image(features)

    x = torch.tensor(img, dtype=torch.float32).unsqueeze(0).unsqueeze(0)

    with torch.no_grad():
        logits = model(x)
        probs = torch.softmax(logits, dim=1)

    ben_prob = probs[0][0].item()
    mal_prob = probs[0][1].item()

    # ✅ define label
    if mal_prob >= MALICIOUS_THRESHOLD:
        label = "MALICIOUS"
        confidence = mal_prob
    elif ben_prob >= BENIGN_THRESHOLD:
        label = "BENIGN"
        confidence = ben_prob
    else:
        label = "UNCERTAIN"
        confidence = max(ben_prob, mal_prob)

    return {
        "label": label,
        "confidence": confidence,
        "benign_prob": ben_prob,
        "malicious_prob": mal_prob
    }
