import torch
import numpy as np
from torch.utils.data import Dataset
from traffic.features import encode_flow
from traffic.utils import flow_to_image
from traffic.flows import extract_flows

class PCAPDataset(Dataset):
    def __init__(self, pcap_files, label):
        self.samples = []

        for pcap in pcap_files:
            flows = extract_flows(pcap)

            for flow in flows.values():
                if len(flow) >= 10:
                    features = encode_flow(flow)
                    image = flow_to_image(features)

                    # pad to 32x32
                    padded = np.zeros((32, 32))
                    padded[:, :image.shape[1]] = image

                    self.samples.append(
                        (padded, label)
                    )

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        img, label = self.samples[idx]
        img = torch.tensor(img).unsqueeze(0).float()
        return img, torch.tensor(label)
