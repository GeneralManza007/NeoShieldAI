import torch
from torch.utils.data import DataLoader, ConcatDataset
from ml.model import TrafficCNN
from ml.dataset import PCAPDataset

BENIGN_PCUPS = ["dataset/benign/benign.pcap"]
MALICIOUS_PCUPS = ["dataset/malicious/malicious.pcap"]

benign_ds = PCAPDataset(BENIGN_PCUPS, label=0)
mal_ds = PCAPDataset(MALICIOUS_PCUPS, label=1)

dataset = ConcatDataset([benign_ds, mal_ds])
loader = DataLoader(dataset, batch_size=16, shuffle=True)

model = TrafficCNN()
model.train()
optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
loss_fn = torch.nn.CrossEntropyLoss()

for epoch in range(10):
    total_loss = 0
    for X, y in loader:
        optimizer.zero_grad()
        preds = model(X)
        loss = loss_fn(preds, y)
        loss.backward()
        optimizer.step()
        total_loss += loss.item()

    print(f"Epoch {epoch+1}, Loss: {total_loss:.4f}")

torch.save(model.state_dict(), "ml/weights.pth")
print("✅ Model trained and saved")
