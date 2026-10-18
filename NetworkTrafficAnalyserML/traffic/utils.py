import numpy as np
import cv2

def flow_to_image(features):
    """
    Always returns a 32x32 grayscale image
    """
    img = np.zeros((32, 32), dtype=np.float32)

    features = np.array(features, dtype=np.float32)

    h = min(features.shape[0], 32)
    w = min(features.shape[1], 32)

    img[:h, :w] = features[:h, :w]

    img = cv2.normalize(img, None, 0, 255, cv2.NORM_MINMAX)
    return img.astype(np.uint8)
