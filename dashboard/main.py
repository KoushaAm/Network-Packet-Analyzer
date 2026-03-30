"""
PacketWatch Dashboard — FastAPI backend
- Trains IsolationForest on packets_normal.csv at startup
- Reads live packets from /tmp/packet_stream named pipe
- Scores each packet in real-time
- Broadcasts scored packets + stats to WebSocket clients
"""

import asyncio
import json
import os
import time
import threading
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

import pandas as pd
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

PIPE_PATH = "/tmp/packet_stream"
NORMAL_CSV = Path(__file__).parent.parent / "packets_normal.csv"
STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI()


# Packet Scorer 

class PacketScorer:
    """Trains IsolationForest on normal traffic; scores single packets in real-time."""

    def __init__(self):
        self._protocol_enc: dict[str, int] = {}
        self._src_ip_enc: dict[str, int] = {}
        self._dst_ip_enc: dict[str, int] = {}
        self._np = self._ns = self._nd = 0
        self.pipeline: Pipeline | None = None
        self.ready = False
        self.trained_on = 0

    def _encode(self, val, enc: dict, counter: list) -> int:
        key = str(val).strip() if val else "MISSING"
        if key not in enc:
            enc[key] = counter[0]
            counter[0] += 1
        return enc[key]

    def _to_features(self, row: dict) -> list[float]:
        ts = str(row.get("timestamp", ""))
        try:
            dt = datetime.strptime(ts[:19], "%Y-%m-%d %H:%M:%S")
            secs = float(dt.hour * 3600 + dt.minute * 60 + dt.second)
        except Exception:
            secs = 0.0

        np_ctr = [self._np]
        ns_ctr = [self._ns]
        nd_ctr = [self._nd]

        proto_id = self._encode(row.get("protocol"), self._protocol_enc, np_ctr)
        src_id   = self._encode(row.get("src_ip"),   self._src_ip_enc,   ns_ctr)
        dst_id   = self._encode(row.get("dst_ip"),   self._dst_ip_enc,   nd_ctr)

        self._np = np_ctr[0]
        self._ns = ns_ctr[0]
        self._nd = nd_ctr[0]

        return [
            secs,
            float(proto_id),
            float(src_id),
            float(dst_id),
            float(row.get("src_port") or 0),
            float(row.get("dst_port") or 0),
            float(row.get("length") or 0),
        ]

    def train(self, csv_path: str):
        df = pd.read_csv(csv_path)
        df.columns = [c.lower().strip() for c in df.columns]
        X = [self._to_features(r) for r in df.to_dict("records")]
        self.pipeline = Pipeline([
            ("scaler", StandardScaler()),
            ("clf", IsolationForest(
                n_estimators=200,
                contamination=0.05,
                random_state=42,
                n_jobs=-1,
            )),
        ])
        self.pipeline.fit(X)
        self.trained_on = len(X)
        self.ready = True
        print(f"[scorer] Model ready — trained on {len(X)} packets from {csv_path}")

    def score(self, row: dict) -> tuple[float, bool]:
        if not self.ready or self.pipeline is None:
            return 0.0, False
        X = [self._to_features(row)]
        scaler = self.pipeline.named_steps["scaler"]
        clf    = self.pipeline.named_steps["clf"]
        Xt = scaler.transform(X)
        raw_score  = float(clf.decision_function(Xt)[0])
        is_anomaly = bool(clf.predict(Xt)[0] == -1)  # cast numpy.bool_ → Python bool
        # invert so higher score = more anomalous (range roughly 0-1)
        anomaly_score = round(float(-raw_score), 4)
        return anomaly_score, is_anomaly


scorer = PacketScorer()


# Live State

class LiveState:
    total: int = 0
    anomalies: int = 0
    protocol_counts: dict = defaultdict(int)
    recent_scores: deque = deque(maxlen=120)   # last 120 packets for timeline
    recent_packets: deque = deque(maxlen=60)   # last 60 for table
    recent_alerts: deque  = deque(maxlen=20)   # anomalies only
    _start = time.time()
    _pps_count: int = 0
    _pps_ts: float = time.time()
    pps: float = 0.0

    @classmethod
    def ingest(cls, pkt: dict):
        cls.total += 1
        if pkt["is_anomaly"]:
            cls.anomalies += 1
            cls.recent_alerts.appendleft(pkt)
        cls.protocol_counts[pkt["protocol"]] += 1
        cls.recent_scores.append({
            "seq":   cls.total,
            "score": pkt["anomaly_score"],
            "anom":  pkt["is_anomaly"],
        })
        cls.recent_packets.appendleft(pkt)

        now = time.time()
        if now - cls._pps_ts >= 1.0:
            cls.pps = round((cls.total - cls._pps_count) / (now - cls._pps_ts), 1)
            cls._pps_count = cls.total
            cls._pps_ts = now

    @classmethod
    def snapshot(cls) -> dict:
        rate = round(cls.anomalies / cls.total * 100, 2) if cls.total else 0.0
        return {
            "total":            cls.total,
            "anomalies":        cls.anomalies,
            "anomaly_rate":     rate,
            "pps":              cls.pps,
            "protocol_counts":  dict(cls.protocol_counts),
        }


# WebSocket clients 

clients: list[WebSocket] = []


async def broadcast(payload: dict):
    dead = []
    for ws in clients:
        try:
            await ws.send_json(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in clients:
            clients.remove(ws)


# Named pipe reader (background thread) : written by sniffer

packet_queue: asyncio.Queue = asyncio.Queue()


def _parse_csv_line(line: str) -> dict | None:
    """Parse: timestamp,protocol,src_ip,src_port,dst_ip,dst_port,length"""
    parts = line.split(",")
    if len(parts) < 7:
        return None
    try:
        return {
            "timestamp": parts[0].strip(),
            "protocol":  parts[1].strip(),
            "src_ip":    parts[2].strip(),
            "src_port":  parts[3].strip(),
            "dst_ip":    parts[4].strip(),
            "dst_port":  parts[5].strip(),
            "length":    parts[6].strip(),
        }
    except Exception:
        return None


def _pipe_thread(loop: asyncio.AbstractEventLoop):
    """Opens the named pipe and pushes lines into the async queue."""
    if not os.path.exists(PIPE_PATH):
        os.mkfifo(PIPE_PATH)
        print(f"[pipe] Created {PIPE_PATH}")

    while True:
        try:
            print("[pipe] Waiting for sniffer to connect…")
            with open(PIPE_PATH, "r") as f:
                print("[pipe] Sniffer connected — streaming packets.")
                for line in f:
                    line = line.strip()
                    if line and not line.lower().startswith("timestamp"):
                        asyncio.run_coroutine_threadsafe(
                            packet_queue.put(line), loop
                        )
            print("[pipe] Sniffer disconnected.")
        except Exception as e:
            print(f"[pipe] Error: {e} — retrying in 0.5s")
            time.sleep(0.5)


# ── Packet processor (async task)

async def _packet_processor():
    while True:
        line = await packet_queue.get()
        row  = _parse_csv_line(line)
        if row is None:
            continue

        score, is_anomaly = scorer.score(row)
        pkt = {
            **row,
            "anomaly_score": score,
            "is_anomaly":    is_anomaly,
        }
        LiveState.ingest(pkt)

        await broadcast({
            "type":          "packet",
            "packet":        pkt,
            "stats":         LiveState.snapshot(),
            "recent_scores": list(LiveState.recent_scores),
        })


#  App lifecycle 

@app.on_event("startup")
async def _startup():
    scorer.train(str(NORMAL_CSV))
    loop = asyncio.get_event_loop()
    threading.Thread(target=_pipe_thread, args=(loop,), daemon=True).start()
    asyncio.create_task(_packet_processor())


#  Routes 

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/state")
async def api_state():
    return {
        "stats":          LiveState.snapshot(),
        "recent_packets": list(LiveState.recent_packets),
        "recent_scores":  list(LiveState.recent_scores),
        "recent_alerts":  list(LiveState.recent_alerts),
        "model_ready":    scorer.ready,
        "trained_on":     scorer.trained_on,
    }


@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()
    clients.append(websocket)

    # send full current state to the new client
    await websocket.send_json({
        "type":           "init",
        "stats":          LiveState.snapshot(),
        "recent_packets": list(LiveState.recent_packets),
        "recent_scores":  list(LiveState.recent_scores),
        "recent_alerts":  list(LiveState.recent_alerts),
        "model_ready":    scorer.ready,
        "trained_on":     scorer.trained_on,
    })

    try:
        while True:
            # keep-alive: client can send anything, we just echo back
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in clients:
            clients.remove(websocket)
