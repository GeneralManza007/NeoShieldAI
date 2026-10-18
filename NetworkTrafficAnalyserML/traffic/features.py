import numpy as np

MAX_PACKETS = 32

def encode_flow(flow):
    """
    Convert a list of scapy packets into a fixed-size
    (32 x 3) feature matrix.
    """
    features = []

    if len(flow) == 0:
        return np.zeros((MAX_PACKETS, 3))

    src_ip = flow[0]["IP"].src
    start_time = flow[0].time

    for pkt in flow[:MAX_PACKETS]:
        size = len(pkt)
        direction = 1 if pkt["IP"].src == src_ip else -1
        delta_time = pkt.time - start_time

        features.append([size, direction, delta_time])

    # Padding
    while len(features) < MAX_PACKETS:
        features.append([0, 0, 0])

    return np.array(features, dtype=np.float32)
