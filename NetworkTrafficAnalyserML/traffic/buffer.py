from collections import defaultdict, deque

MAX_PACKETS = 32

FLOW_BUFFER = defaultdict(lambda: deque(maxlen=MAX_PACKETS))