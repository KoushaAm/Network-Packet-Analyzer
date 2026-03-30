# Packet Sniffer

A network packet sniffer with real-time anomaly detection. The C++ sniffer captures live traffic and streams it to a Python dashboard that scores each packet using an Isolation Forest model trained on normal traffic.

## Gallery
<img width="1365" height="886" alt="Screenshot 2026-03-29 at 6 51 56 PM" src="https://github.com/user-attachments/assets/e4193e7d-5976-4a59-906d-309d612f27f1" />



## How it works

1. The C++ sniffer captures packets via libpcap and writes them to `packets.csv` and a named pipe (`/tmp/packet_stream`)
2. The Python dashboard reads from the pipe, scores each packet in real-time, and broadcasts results over WebSocket
3. The browser dashboard displays live stats, an anomaly score timeline, protocol distribution, and a scrollable packet feed

## Requirements

**C++**
- libpcap (`brew install libpcap` on macOS)
- g++ with C++17

**Python**
```
pip install -r dashboard/requirements.txt
```

## Running

**1. Build the sniffer**
```bash
make
```

**2. Start the dashboard** (in one terminal)
```bash
cd dashboard
uvicorn main:app --reload --port 8000
```

**3. Start the sniffer** (in another terminal, requires root)
```bash
sudo ./sniffer en0
```

Replace `en0` with your network interface. Find yours with `ifconfig` or `ip link`.

**4. Open the dashboard**

Go to `http://localhost:8000` in your browser.

## Project structure

```
Packet-Sniffer/
├── src/                  # C++ source (sniffer, parser, logger, display)
├── include/              # C++ headers
├── dashboard/
│   ├── main.py           # FastAPI backend, model training, WebSocket
│   └── static/
│       └── index.html    # Browser dashboard
├── anamoly_detector/
│   └── analysis.py       # Offline batch analysis script
├── data/extraction/out/  # Test datasets (malformed, syn scan, udp burst)
├── packets_normal.csv    # Normal traffic used to train the model
├── packets.csv           # Live capture output
└── Makefile
```

## Dashboard features

- Live packet feed with anomaly highlighting
- Anomaly score timeline chart (last 120 packets)
- Protocol distribution chart
- Recent alerts panel (anomalies only)
- Pause/Resume button to freeze the display

## Model

Isolation Forest trained on `packets_normal.csv` (1,502 packets). Features: time of day, protocol, source/destination IP and port, packet length. Packets scoring above the threshold are flagged as anomalies.
