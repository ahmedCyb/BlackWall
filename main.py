import json
import time
import math
import os
import sys
import logging
import subprocess
import threading
import requests
from collections import defaultdict
import glob
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from imblearn.over_sampling import SMOTE
from xgboost import XGBClassifier
from collections import Counter
import joblib
from collections import Counter
# ─── Logging setup ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("ids.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger(__name__)

# ─── Config ───────────────────────────────────────────────────────────────────
PIPE_PATH = "/home/marcus/projects/networkSec/packet_pipe"
FLOW_TIMEOUT = 60
MIN_PACKETS = 3
MODEL_PATH = "ids_model.joblib"
SCALER_PATH = "ids_scaler.joblib"
LABEL_ENCODER_PATH = "ids_label_encoder.joblib"
ANOMALY_MODEL_PATH = "anomaly_model.joblib"
ANOMALY_SCALER_PATH = "anomaly_scaler.joblib"
ALERT_LOG = "alerts.jsonl"
AUTH_PORTS = {"22", "21", "23", "3389", "5900"}

# ─── Prevention config ────────────────────────────────────────────────────────
BLOCK_DURATION = 300      # seconds to block an IP
CONFIDENCE_THRESHOLD = 0.95     # minimum confidence to trigger block
AUTO_BLOCK_CLASSES = {"syn_flood", "port_scan", "brute_force"}


WHITELIST = {
    "127.0.0.1",
    "192.168.100.42",   # own machine
    "192.168.100.1",    # router/gateway
}

# ─── Ollama LLM config ────────────────────────────────────────────────────────
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3"
LLM_ENABLED = True

# ─── Scan detection config ────────────────────────────────────────────────────
SCAN_WINDOW = 15
SCAN_PKT_THRESHOLD = 100

# ─── Feature columns ──────────────────────────────────────────────────────────
FEATURE_COLS = [
    "pkt_count", "total_bytes", "bytes_per_pkt", "pkts_per_sec",
    "bytes_per_sec", "duration_sec", "syn_ratio", "ack_ratio",
    "fin_ratio", "rst_ratio", "push_ratio", "mean_pkt_size", "std_pkt_size",
]

# ─── Runtime state ────────────────────────────────────────────────────────────
flows = defaultdict(lambda: {
    "packets": [], "first_seen": None, "last_seen": None,
    "total_bytes": 0, "syn_count": 0, "ack_count": 0,
    "fin_count": 0, "rst_count": 0, "push_count": 0,
})
src_activity = defaultdict(lambda: {
    "dst_ports": set(), "first_seen": None, "pkt_count": 0,
})
syn_tracker = defaultdict(lambda: {
    "syn_count":  0,
    "first_seen": None,
})
brute_tracker = defaultdict(lambda: {
    "connection_count": 0,
    "first_seen":       None,
})

BRUTE_WINDOW     = 30   # seconds
BRUTE_THRESHOLD  = 10   # connections to auth port in window

SYN_FLOOD_WINDOW    = 5    # seconds
SYN_FLOOD_THRESHOLD = 500  # SYN packets from same IP in window

blocked_ips = set()

# ─── ANSI colors ──────────────────────────────────────────────────────────────
COLORS = {
    "benign":            "\033[32m",
    "syn_flood":         "\033[31m",
    "port_scan":         "\033[33m",
    "brute_force":       "\033[31m",
    "data_exfiltration": "\033[31m",
    "c2_communication":  "\033[35m",
    "anomaly":           "\033[36m",
    "error":             "\033[90m",
}
RESET = "\033[0m"


# ─────────────────────────────────────────────────────────────────────────────
# FLOW INGESTION
# ─────────────────────────────────────────────────────────────────────────────

def flow_key(pkt):
    return (
        pkt.get("src_ip",   "?"),
        pkt.get("dst_ip",   "?"),
        str(pkt.get("src_port", "?")),
        str(pkt.get("dst_port", "?")),
        pkt.get("protocol", "?"),
    )


def ingest(pkt):
    key = flow_key(pkt)
    flow = flows[key]
    now = time.time()

    if flow["first_seen"] is None:
        flow["first_seen"] = now
    flow["last_seen"] = now
    flow["total_bytes"] += pkt.get("payload_len", 0)
    flow["packets"].append(pkt)

    flags = pkt.get("flags", "")
    if "SYN" in flags:
        flow["syn_count"] += 1
    if "ACK" in flags:
        flow["ack_count"] += 1
    if "FIN" in flags:
        flow["fin_count"] += 1
    if "RST" in flags:
        flow["rst_count"] += 1
    if "PUSH" in flags:
        flow["push_count"] += 1

    if "FIN" in flags or "RST" in flags:
        return key
    if len(flow["packets"]) == 500:
        return key
    return None


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────

def extract_features(key, flow):
    src_ip, dst_ip, src_port, dst_port, protocol = key
    pkts = flow["packets"]
    n = len(pkts)
    duration = max(flow["last_seen"] - flow["first_seen"], 0.001)

    sizes = [p.get("payload_len", 0) for p in pkts]
    mean_size = sum(sizes) / n
    variance = sum((s - mean_size) ** 2 for s in sizes) / n
    std_size = math.sqrt(variance)

    return {
        "src_ip":        src_ip,
        "dst_ip":        dst_ip,
        "src_port":      src_port,
        "dst_port":      dst_port,
        "protocol":      protocol,
        "pkt_count":     math.log1p(n),
        "total_bytes":   math.log1p(flow["total_bytes"]),
        "bytes_per_pkt": math.log1p(flow["total_bytes"] / n),
        "pkts_per_sec":  math.log1p(n / duration),
        "bytes_per_sec": math.log1p(flow["total_bytes"] / duration),
        "duration_sec":  math.log1p(duration),
        "syn_ratio":     flow["syn_count"] / n,
        "ack_ratio":     flow["ack_count"] / n,
        "fin_ratio":     flow["fin_count"] / n,
        "rst_ratio":     flow["rst_count"] / n,
        "push_ratio":    flow["push_count"] / n,
        "mean_pkt_size": math.log1p(mean_size),
        "std_pkt_size":  math.log1p(std_size),
    }


def to_vector(features):
    return np.array([[features[col] for col in FEATURE_COLS]])


# ─────────────────────────────────────────────────────────────────────────────
# RULE-BASED CLASSIFIER (fallback when no model trained)
# ─────────────────────────────────────────────────────────────────────────────

def rule_based_classify(features):
    syn_ratio = features["syn_ratio"]
    ack_ratio = features["ack_ratio"]
    rst_ratio = features["rst_ratio"]
    dst_port = str(features["dst_port"])
    pkt_count = math.expm1(features["pkt_count"])
    bytes_per_sec = math.expm1(features["bytes_per_sec"])
    duration_sec = math.expm1(features["duration_sec"])
    mean_pkt_size = math.expm1(features["mean_pkt_size"])

    if syn_ratio > 0.9 and ack_ratio < 0.05:
        if pkt_count < 50:
            return {"classification": "benign", "confidence": 0.70,
                    "reason": "SYN pattern but too few packets"}
        return {"classification": "syn_flood", "confidence": 0.95,
                "reason": f"SYN ratio {syn_ratio:.2f}, ACK ratio {ack_ratio:.2f}"}

    if mean_pkt_size < 8 and pkt_count > 30:
        return {"classification": "port_scan", "confidence": 0.87,
                "reason": f"{pkt_count:.0f} packets, near-zero payload"}

    if rst_ratio > 0.7 and pkt_count > 20:
        return {"classification": "port_scan", "confidence": 0.82,
                "reason": f"High RST ratio {rst_ratio:.2f} — stealth scan"}

    if dst_port in AUTH_PORTS and pkt_count > 80 and duration_sec < 15:
        return {"classification": "brute_force", "confidence": 0.90,
                "reason": f"{pkt_count:.0f} packets to auth port {dst_port}"}

    if bytes_per_sec > 500_000 and duration_sec > 5:
        return {"classification": "data_exfiltration", "confidence": 0.78,
                "reason": f"{bytes_per_sec/1000:.1f} KB/s for {duration_sec:.1f}s"}

    non_standard = dst_port not in {
        "80", "443", "53", "22", "21", "8080", "8443", "123", "67", "68"}
    if non_standard and 10 < pkt_count < 30 and mean_pkt_size < 50 and duration_sec > 2:
        return {"classification": "c2_communication", "confidence": 0.70,
                "reason": f"Periodic small packets on port {dst_port}"}

    return {"classification": "benign", "confidence": 0.88,
            "reason": "No anomalous patterns detected"}


# ─────────────────────────────────────────────────────────────────────────────
# XGBOOST CLASSIFIER
# ─────────────────────────────────────────────────────────────────────────────

class IDSModel:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.classes = None
        self._load_if_exists()

    def _load_if_exists(self):
        if (os.path.exists(MODEL_PATH) and
                os.path.exists(SCALER_PATH) and
                os.path.exists(LABEL_ENCODER_PATH)):
            log.info("Loading trained XGBoost model from disk...")
            self.model = joblib.load(MODEL_PATH)
            self.scaler = joblib.load(SCALER_PATH)
            self.label_encoder = joblib.load(LABEL_ENCODER_PATH)
            self.classes = self.label_encoder.classes_
            log.info(f"Model loaded. Classes: {self.classes}")
        else:
            log.info("No trained model found — using rule-based classifier")

    def is_trained(self):
        return self.model is not None

    def train(self, records, labels):
        log.info(f"Training XGBoost on {len(records)} samples...")

        X = np.array([[r[col] for col in FEATURE_COLS] for r in records])
        y = np.array(labels)

        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()

        X_scaled = self.scaler.fit_transform(X)
        y_encoded = self.label_encoder.fit_transform(y)
        self.classes = self.label_encoder.classes_

        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
        )
        classes = self.label_encoder.classes_.tolist()
        strategy_named = {
            "brute_force":       80000,   # was 50000
            "c2_communication":  80000,   # was 50000
            "data_exfiltration": 30000,   # was 10000
        }
        # Only include classes that actually exist in y_train
        strategy_encoded = {}
        for cls_name, target_count in strategy_named.items():
            if cls_name in classes:
                cls_idx = classes.index(cls_name)
                current_count = int(np.sum(y_train == cls_idx))
                if current_count > 0 and target_count > current_count:
                    strategy_encoded[cls_idx] = target_count

        log.info(f"SMOTE targets: {strategy_encoded}")

        smote = SMOTE(
            sampling_strategy=strategy_encoded,
            k_neighbors=5,
            random_state=42
        )
        X_resampled, y_resampled = smote.fit_resample(X_train, y_train)
        log.info(f"After SMOTE: {len(X_resampled)} samples")

        self.model = XGBClassifier(
            n_estimators=500,
            max_depth=10,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            eval_metric="mlogloss",
            n_jobs=-1,
            random_state=42,
            tree_method="hist",
            early_stopping_round=20,
        )
        self.model.fit(
            X_resampled, y_resampled,

            eval_set=[(X_test, y_test)],
            verbose=50
        )

        y_pred = self.model.predict(X_test)
        y_pred_labels = self.label_encoder.inverse_transform(y_pred)
        y_test_labels = self.label_encoder.inverse_transform(y_test)
        log.info("\n" + classification_report(y_test_labels, y_pred_labels))

        joblib.dump(self.model,         MODEL_PATH)
        joblib.dump(self.scaler,        SCALER_PATH)
        joblib.dump(self.label_encoder, LABEL_ENCODER_PATH)
        log.info(f"Model saved to {MODEL_PATH}")

    def predict(self, features):
        X = to_vector(features)
        X_scaled = self.scaler.transform(X)

        encoded = self.model.predict(X_scaled)[0]
        label = self.label_encoder.inverse_transform([encoded])[0]
        probabilities = self.model.predict_proba(X_scaled)[0]
        confidence = float(probabilities.max())

        importances = self.model.feature_importances_
        top_idx = np.argsort(importances)[::-1][:3]
        top_features = [f"{FEATURE_COLS[i]}={features[FEATURE_COLS[i]]:.3f}"
                        for i in top_idx]
        reason = "Top features: " + ", ".join(top_features)

        # Minimum packets check
        pkt_count = math.expm1(features["pkt_count"])
        min_pkts = {
            "syn_flood":         50,
            "port_scan":         20,
            "brute_force":       30,
            "c2_communication":  8,
            "data_exfiltration": 20,
        }
        if label != "benign" and pkt_count < min_pkts.get(label, 0):
            return {
                "classification": "benign",
                "confidence":     0.70,
                "reason":         f"Too few packets ({pkt_count:.0f}) for {label}",
            }

        return {
            "classification": label,
            "confidence":     round(confidence, 3),
            "reason":         reason,
        }


# ─────────────────────────────────────────────────────────────────────────────
# ISOLATION FOREST — zero-day anomaly detection
# ─────────────────────────────────────────────────────────────────────────────

class AnomalyDetector:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.trained = False
        self._load_if_exists()

    def _load_if_exists(self):
        if os.path.exists(ANOMALY_MODEL_PATH) and os.path.exists(ANOMALY_SCALER_PATH):
            log.info("Loading Isolation Forest from disk...")
            self.model = joblib.load(ANOMALY_MODEL_PATH)
            self.scaler = joblib.load(ANOMALY_SCALER_PATH)
            self.trained = True

    def train(self, records):
        """Train ONLY on benign flows — anything different = anomaly."""
        log.info(f"Training Isolation Forest on {
                 len(records)} benign samples...")
        X = np.array([[r[col] for col in FEATURE_COLS] for r in records])
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.model = IsolationForest(
            n_estimators=200,
            contamination=0.001,
            random_state=42,
            n_jobs=-1
        )
        self.model.fit(X_scaled)
        self.trained = True

        joblib.dump(self.model,  ANOMALY_MODEL_PATH)
        joblib.dump(self.scaler, ANOMALY_SCALER_PATH)
        log.info("Isolation Forest saved.")

    def predict(self, features):
        X = to_vector(features)
        X_scaled = self.scaler.transform(X)
        score = self.model.decision_function(X_scaled)[0]
        label = self.model.predict(X_scaled)[0]
        return {
            "is_anomaly":    label == -1,
            "anomaly_score": round(float(score), 4),
        }


# ─────────────────────────────────────────────────────────────────────────────
# LLM THREAT EXPLANATION (local Ollama)
# ─────────────────────────────────────────────────────────────────────────────

def llm_explain(features, result):
    """
    Ask local Llama 3 to explain the threat and suggest an iptables rule.
    Runs in a background thread — never blocks packet processing.
    """
    if not LLM_ENABLED:
        return
    if result["classification"] == "benign":
        return
    if result["confidence"] < CONFIDENCE_THRESHOLD:
        return

    prompt = f"""You are a network security analyst reviewing an IDS alert.

Classification : {result['classification']}
Confidence     : {result['confidence']}
Source IP      : {features['src_ip']}:{features['src_port']}
Destination    : {features['dst_ip']}:{features['dst_port']}
Protocol       : {features['protocol']}
Packets/sec    : {math.expm1(features['pkts_per_sec']):.1f}
SYN ratio      : {features['syn_ratio']:.3f}
ACK ratio      : {features['ack_ratio']:.3f}
Bytes/sec      : {math.expm1(features['bytes_per_sec']):.0f}

Respond with exactly 3 sections:
1. EXPLANATION (2 sentences max — what is this attack doing)
2. IPTABLES RULE (one-liner to block it)
3. RISK LEVEL (one word: LOW / MEDIUM / HIGH / CRITICAL)"""

    try:
        response = requests.post(OLLAMA_URL, json={
            "model":  OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
        }, timeout=30)
        explanation = response.json().get("response", "").strip()
        print(f"\n{COLORS['c2_communication']}LLM Analysis:{
              RESET}\n{explanation}\n")
    except requests.exceptions.ConnectionError:
        log.warning("Ollama not running — skipping LLM explanation. "
                    "Start with: ollama serve")
    except Exception as e:
        log.warning(f"LLM error: {e}")


def llm_explain_async(features, result):
    """Fire-and-forget LLM call that never blocks the main loop."""
    t = threading.Thread(target=llm_explain, args=(features, result))
    t.daemon = True
    t.start()


# ─────────────────────────────────────────────────────────────────────────────
# IPTABLES PREVENTION
# ─────────────────────────────────────────────────────────────────────────────

def is_safe_to_block(ip):
    if ip in WHITELIST:
        return False
    if ip.startswith("127."):
        return False
    # Private ranges — blocked by default, set to True to allow blocking them
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
        return True
    return True


def block_ip(src_ip, reason, duration=BLOCK_DURATION):
    if src_ip in blocked_ips:
        return
    if not is_safe_to_block(src_ip):
        log.info(f"BLOCK SKIPPED (whitelisted/private): {src_ip}")
        return

    comment = f"ml-ids:{reason[:30]}"

    try:
        subprocess.run([
            "iptables", "-I", "INPUT",
            "-s", src_ip,
            "-j", "DROP",
            "-m", "comment",
            "--comment", comment
        ], check=True, capture_output=True)

        blocked_ips.add(src_ip)
        log.warning(f"{COLORS['syn_flood']}BLOCKED{RESET} "
                    f"{src_ip} for {duration}s — {reason}")

        # Schedule auto-unblock in background thread
        def unblock():
            time.sleep(duration)
            try:
                subprocess.run([
                    "iptables", "-D", "INPUT",
                    "-s", src_ip,
                    "-j", "DROP",
                    "-m", "comment",
                    "--comment", comment
                ], check=True, capture_output=True)
                blocked_ips.discard(src_ip)
                log.info(f"UNBLOCKED {src_ip} after {duration}s")
            except subprocess.CalledProcessError as e:
                log.warning(f"Failed to unblock {src_ip}: {e}")

        t = threading.Thread(target=unblock)
        t.daemon = True
        t.start()

    except subprocess.CalledProcessError as e:
        log.error(f"iptables failed for {src_ip}: {e.stderr.decode()}")
        log.error("Run with sudo for iptables access: sudo python3 main.py")


# ─────────────────────────────────────────────────────────────────────────────
# ALERTING
# ─────────────────────────────────────────────────────────────────────────────

def alert(features, result):
    cls = result["classification"]
    confidence = result["confidence"]
    color = COLORS.get(cls, RESET)

    # Suppress low-confidence non-benign to reduce false positives
    # if cls != "benign" and confidence < 0.95:
    #   return

    print(
        f"{color}[{cls.upper():>18}]{RESET} "
        f"{features['src_ip']:>15}:{str(features['src_port']):<6} → "
        f"{features['dst_ip']:>15}:{str(features['dst_port']):<6} "
        f"| pkts: {math.expm1(features['pkt_count']):>6.0f} "
        f"| conf: {confidence:.2f} "
        f"| {result['reason']}"
    )

    if cls != "benign":
        # Write to alert log
        with open(ALERT_LOG, "a") as f:
            record = {
                "timestamp":      time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "classification": cls,
                "confidence":     confidence,
                "src_ip":         features["src_ip"],
                "dst_ip":         features["dst_ip"],
                "src_port":       features["src_port"],
                "dst_port":       features["dst_port"],
                "protocol":       features["protocol"],
                "reason":         result["reason"],
            }
            f.write(json.dumps(record) + "\n")

        # LLM explanation async — won't block packet processing
        if confidence >= CONFIDENCE_THRESHOLD:
            llm_explain_async(features, result)

        # Auto-block high confidence known attacks
        if cls in AUTO_BLOCK_CLASSES and confidence >= CONFIDENCE_THRESHOLD:
            block_ip(
                features["src_ip"],
                reason=f"{cls}(conf={confidence:.2f})"
            )


# ─────────────────────────────────────────────────────────────────────────────
# PORT SCAN TRACKER (cross-flow detection)
# ─────────────────────────────────────────────────────────────────────────────

def track_source(pkt):
    src = pkt.get("src_ip")
    dst_port = str(pkt.get("dst_port", ""))
    if not src or not dst_port:
        return

    now = time.time()
    activity = src_activity[src]

    if activity["first_seen"] is None:
        activity["first_seen"] = now

    activity["dst_ports"].add(dst_port)
    activity["pkt_count"] += 1

    if now - activity["first_seen"] > SCAN_WINDOW:
        activity["dst_ports"] = {dst_port}
        activity["first_seen"] = now
        activity["pkt_count"] = 1
        return

    if len(activity["dst_ports"]) > SCAN_PKT_THRESHOLD:
        elapsed = now - activity["first_seen"]
        print(f"{COLORS['port_scan']}[         PORT_SCAN]{RESET} "
              f"{src:>15} scanned "
              f"{len(activity['dst_ports'])} ports in {elapsed:.1f}s")

        with open(ALERT_LOG, "a") as f:
            f.write(json.dumps({
                "timestamp":      time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "classification": "port_scan",
                "confidence":     0.99,
                "src_ip":         src,
                "dst_ip":         pkt.get("dst_ip"),
                "ports_scanned":  len(activity["dst_ports"]),
                "reason":         f"Hit {len(activity['dst_ports'])} unique ports in {elapsed:.1f}s",
            }) + "\n")

        block_ip(src, reason=f"port_scan({len(activity['dst_ports'])}ports)")

        activity["dst_ports"] = set()
        activity["first_seen"] = now
        activity["pkt_count"] = 0

    
def track_syn_flood(pkt):
    if "SYN" not in pkt.get("flags", ""):
        return
    if "ACK" in pkt.get("flags", ""):
        return  # SYN-ACK is normal, ignore

    src = pkt.get("src_ip")
    if not src:
        return

    now     = time.time()
    tracker = syn_tracker[src]

    if tracker["first_seen"] is None:
        tracker["first_seen"] = now

    # Reset window if expired
    if now - tracker["first_seen"] > SYN_FLOOD_WINDOW:
        tracker["syn_count"]  = 1
        tracker["first_seen"] = now
        return

    tracker["syn_count"] += 1

    if tracker["syn_count"] >= SYN_FLOOD_THRESHOLD:
        rate = tracker["syn_count"] / (now - tracker["first_seen"])
        print(f"{COLORS['syn_flood']}[          SYN_FLOOD]{RESET} "
              f"{src:>15} sent {tracker['syn_count']} SYNs "
              f"in {now - tracker['first_seen']:.1f}s "
              f"({rate:.0f} pkts/s)")

        with open(ALERT_LOG, "a") as f:
            f.write(json.dumps({
                "timestamp":      time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "classification": "syn_flood",
                "confidence":     0.99,
                "src_ip":         src,
                "dst_ip":         pkt.get("dst_ip"),
                "syn_count":      tracker["syn_count"],
                "reason":         f"{tracker['syn_count']} SYNs in {now - tracker['first_seen']:.1f}s",
            }) + "\n")

        block_ip(src, reason=f"syn_flood({tracker['syn_count']}syns)")

        # Reset after alert
        tracker["syn_count"]  = 0
        tracker["first_seen"] = now

def track_brute_force(pkt):
    """Detect brute force by counting connections to auth ports per source."""
    dst_port = str(pkt.get("dst_port", ""))
    if dst_port not in AUTH_PORTS:
        return

    # Only count SYN packets — each SYN = new connection attempt
    if "SYN" not in pkt.get("flags", ""):
        return
    if "ACK" in pkt.get("flags", ""):
        return

    src = pkt.get("src_ip")
    if not src:
        return

    now     = time.time()
    tracker = brute_tracker[src]

    if tracker["first_seen"] is None:
        tracker["first_seen"] = now

    if now - tracker["first_seen"] > BRUTE_WINDOW:
        tracker["connection_count"] = 1
        tracker["first_seen"]       = now
        return

    tracker["connection_count"] += 1

    if tracker["connection_count"] >= BRUTE_THRESHOLD:
        elapsed = now - tracker["first_seen"]
        rate    = tracker["connection_count"] / elapsed

        print(f"{COLORS['brute_force']}[       BRUTE_FORCE]{RESET} "
              f"{src:>15} made {tracker['connection_count']} "
              f"connection attempts to port {dst_port} "
              f"in {elapsed:.1f}s ({rate:.1f}/s)")

        with open(ALERT_LOG, "a") as f:
            f.write(json.dumps({
                "timestamp":        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "classification":   "brute_force",
                "confidence":       0.97,
                "src_ip":           src,
                "dst_ip":           pkt.get("dst_ip"),
                "dst_port":         dst_port,
                "connection_count": tracker["connection_count"],
                "reason":           f"{tracker['connection_count']} auth attempts in {elapsed:.1f}s",
            }) + "\n")

        block_ip(src, reason=f"brute_force(port{dst_port})")

        # Reset after alert
        tracker["connection_count"] = 0
        tracker["first_seen"]       = now

# ─────────────────────────────────────────────────────────────────────────────
# FLOW LIFECYCLE
# ─────────────────────────────────────────────────────────────────────────────

def check_expired_flows():
    now = time.time()
    return [
        key for key, flow in flows.items()
        if flow["last_seen"] and now - flow["last_seen"] > FLOW_TIMEOUT
    ]


def process_flow(key, model, anomaly_detector):
    flow = flows.pop(key, None)
    if flow is None:
        return
    if len(flow["packets"]) < MIN_PACKETS:
        return

    src_ip, dst_ip, src_port, dst_port, protocol = key

    if src_ip == dst_ip:
        return

    features = extract_features(key, flow)
    print(f"DEBUG: Flow to {features['dst_ip']} | SYN Ratio: {
          features['syn_ratio']:.4f} | Pkts: {math.expm1(features['pkt_count'])}")
    # Layer 1: XGBoost / rule-based classification
    if model.is_trained():
        result = model.predict(features)

        if result["classification"] == "port_scan" and features["syn_ratio"] > 0.98:
            result["classification"] = "syn_flood"
            result["confidence"] = 0.99
            result["reason"] += " (Correction: 100% SYN ratio detected)"
    else:
        result = rule_based_classify(features)

    # Layer 2: Isolation Forest zero-day detection
    # Only fires if XGBoost said benign, catches what it missed
    if anomaly_detector.trained and result["classification"] == "benign":
        anomaly = anomaly_detector.predict(features)
        if anomaly["is_anomaly"] and anomaly["anomaly_score"] < -0.15:
            result = {
                "classification": "anomaly",
                "confidence":     min(abs(anomaly["anomaly_score"]) * 10, 0.99),
                "reason":         f"Anomalous flow (IF score={anomaly['anomaly_score']:.3f}) — possible zero-day",
            }

    alert(features, result)


# ─────────────────────────────────────────────────────────────────────────────
# CICIDS2017 TRAINING
# ─────────────────────────────────────────────────────────────────────────────

def train_on_cicids_all(csv_folder, model, anomaly_detector):
    all_files = glob.glob(os.path.join(csv_folder, "*.csv"))
    if not all_files:
        log.error(f"No CSV files found in {csv_folder}")
        return

    log.info(f"Found {len(all_files)} CSV files")
    dfs = []
    for f in all_files:
        log.info(f"Loading {os.path.basename(f)}...")
        try:
            df = pd.read_csv(f, encoding="utf-8", low_memory=False)
            df.columns = df.columns.str.strip()
            dfs.append(df)
        except Exception as e:
            log.warning(f"Failed to load {f}: {e}")

    combined = pd.concat(dfs, ignore_index=True)
    log.info(f"Total rows: {len(combined):,}")
    log.info(f"Label distribution:\n{combined['Label'].value_counts()}")
    _train_from_dataframe(combined, model, anomaly_detector)


def generate_exfil_samples(n=5000):
    """
    Synthetic data exfiltration flows.
    Real exfil = high sustained bytes, long duration, low packet variance.
    """
    records = []
    for _ in range(n):
        # Randomize slightly around known exfil characteristics
        pkt_count = np.random.randint(100, 2000)
        total_bytes = np.random.randint(500_000, 50_000_000)
        duration = np.random.uniform(10, 300)

        records.append({
            "pkt_count":     math.log1p(pkt_count),
            "total_bytes":   math.log1p(total_bytes),
            "bytes_per_pkt": math.log1p(total_bytes / pkt_count),
            "pkts_per_sec":  math.log1p(pkt_count / duration),
            "bytes_per_sec": math.log1p(total_bytes / duration),
            "duration_sec":  math.log1p(duration),
            "syn_ratio":     np.random.uniform(0.0, 0.05),
            "ack_ratio":     np.random.uniform(0.4, 0.7),
            "fin_ratio":     np.random.uniform(0.0, 0.05),
            "rst_ratio":     np.random.uniform(0.0, 0.02),
            "push_ratio":    np.random.uniform(0.3, 0.6),
            "mean_pkt_size": math.log1p(np.random.uniform(800, 1400)),
            "std_pkt_size":  math.log1p(np.random.uniform(10, 100)),
        })
    return records, ["data_exfiltration"] * n


def generate_c2_samples(n=5000):
    """
    Synthetic C2 beaconing flows.
    Real C2 = small periodic packets, non-standard ports, low variance.
    """
    records = []
    for _ in range(n):
        pkt_count = np.random.randint(5, 50)
        total_bytes = np.random.randint(100, 5000)
        duration = np.random.uniform(1, 30)

        records.append({
            "pkt_count":     math.log1p(pkt_count),
            "total_bytes":   math.log1p(total_bytes),
            "bytes_per_pkt": math.log1p(total_bytes / pkt_count),
            "pkts_per_sec":  math.log1p(pkt_count / duration),
            "bytes_per_sec": math.log1p(total_bytes / duration),
            "duration_sec":  math.log1p(duration),
            "syn_ratio":     np.random.uniform(0.0, 0.1),
            "ack_ratio":     np.random.uniform(0.4, 0.6),
            "fin_ratio":     np.random.uniform(0.0, 0.05),
            "rst_ratio":     np.random.uniform(0.0, 0.05),
            "push_ratio":    np.random.uniform(0.1, 0.3),
            "mean_pkt_size": math.log1p(np.random.uniform(20, 200)),
            "std_pkt_size":  math.log1p(np.random.uniform(5, 30)),
        })
    return records, ["c2_communication"] * n


def _train_from_dataframe(df, model, anomaly_detector):
    df = df.replace([np.inf, -np.inf], 0).dropna()

    column_map = {
        "Flow Duration":               "duration_sec",
        "Total Fwd Packets":           "pkt_count",
        "Total Length of Fwd Packets": "total_bytes",
        "Flow Bytes/s":                "bytes_per_sec",
        "Flow Packets/s":              "pkts_per_sec",
        "Fwd Packet Length Mean":      "mean_pkt_size",
        "Fwd Packet Length Std":       "std_pkt_size",
        "SYN Flag Count":              "syn_count_raw",
        "ACK Flag Count":              "ack_count_raw",
        "FIN Flag Count":              "fin_count_raw",
        "RST Flag Count":              "rst_count_raw",
        "PSH Flag Count":              "push_count_raw",
        "Label":                       "label",
    }

    available = {k: v for k, v in column_map.items() if k in df.columns}
    missing = set(column_map.keys()) - set(available.keys())
    if missing:
        log.warning(f"Missing columns: {missing}")

    df = df.rename(columns=available)[list(available.values())].dropna()

    df["syn_ratio"] = df["syn_count_raw"] / df["pkt_count"].clip(lower=1)
    df["ack_ratio"] = df["ack_count_raw"] / df["pkt_count"].clip(lower=1)
    df["fin_ratio"] = df["fin_count_raw"] / df["pkt_count"].clip(lower=1)
    df["rst_ratio"] = df["rst_count_raw"] / df["pkt_count"].clip(lower=1)
    df["push_ratio"] = df["push_count_raw"] / df["pkt_count"].clip(lower=1)

    for col in ["pkt_count", "total_bytes", "bytes_per_sec", "pkts_per_sec",
                "mean_pkt_size", "std_pkt_size", "duration_sec"]:
        if col in df.columns:
            df[col] = np.log1p(df[col].clip(lower=0))

    df["bytes_per_pkt"] = np.log1p(
        np.expm1(df["total_bytes"]) / np.expm1(df["pkt_count"]).clip(lower=1)
    )

    label_map = {
        "BENIGN":                     "benign",
        "DDoS":                       "syn_flood",
        "DoS Hulk":                   "syn_flood",
        "DoS GoldenEye":              "syn_flood",
        "DoS slowloris":              "syn_flood",
        "DoS Slowhttptest":           "syn_flood",
        "Heartbleed":                 "syn_flood",
        "PortScan":                   "port_scan",
        "FTP-Patator":                "brute_force",
        "SSH-Patator":                "brute_force",
        "Bot":                        "c2_communication",
        "Infiltration":               "data_exfiltration",
        "Web Attack - Brute Force":   "brute_force",
        "Web Attack - XSS":           "benign",
        "Web Attack - Sql Injection": "benign",
    }
    df["label"] = df["label"].str.strip().map(label_map).fillna("benign")

    records = df[FEATURE_COLS].to_dict("records")
    labels = df["label"].tolist()
    # Inject synthetic samples for weak classes
    exfil_r, exfil_l = generate_exfil_samples(5000)
    c2_r,    c2_l = generate_c2_samples(5000)

    records += exfil_r + c2_r
    labels += exfil_l + c2_l

    log.info(f"Added 10000 synthetic samples for weak classes")
    # Train XGBoost on all labeled data
    model.train(records, labels)

    # Train Isolation Forest on benign flows only
    benign_records = [r for r, l in zip(records, labels) if l == "benign"]
    log.info(f"Training Isolation Forest on {
             len(benign_records):,} benign flows...")
    anomaly_detector.train(benign_records)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────


def main():
    print(r"""
__________.__                 __     __      __        .__  .__   
\______   \  | _____    ____ |  | __/  \    /  \_____  |  | |  |  
 |    |  _/  | \__  \ _/ ___\|  |/ /\   \/\/   /\__  \ |  | |  |  
 |    |   \  |__/ __ \\  \___|    <  \        /  / __ \|  |_|  |__
 |______  /____(____  /\___  >__|_ \  \__/\  /  (____  /____/____/
        \/          \/     \/     \/       \/        \/          
        """)
    model = IDSModel()
    anomaly_detector = AnomalyDetector()

    # --Training
    # train_on_cicids_all(
    #  "/home/marcus/projects/networkSec/cicids2017/", model, anomaly_detector)
    # return

    log.info(f"Classifier    : {
             'XGBoost' if model.is_trained() else 'Rule-based'}")
    log.info(f"Anomaly model : {
             'Isolation Forest' if anomaly_detector.trained else 'Not loaded'}")
    log.info(f"LLM           : {'Ollama/' +
             OLLAMA_MODEL if LLM_ENABLED else 'Disabled'}")
    log.info(f"Prevention    : iptables auto-block {AUTO_BLOCK_CLASSES}")
    log.info(f"Reading from  : {PIPE_PATH}\n")

    try:

        log.info("Waiting for C sniffer to attach to the pipe...")

        with open(PIPE_PATH, "r") as f:
            log.info("Pipe connected! Listening for packets...")
            last_expiry_check = time.time()

            while True:
                line = f.readline()

                # If readline returns empty, the C program closed its end of the pipe
                if not line:
                    log.info("Pipe closed by C program. Shutting down...")
                    break

                line = line.strip()
                if not line:
                    continue

                try:
                    pkt = json.loads(line)
                except json.JSONDecodeError as e:
                    log.warning(f"Bad JSON: {e} — '{line[:60]}'")
                    continue

                track_source(pkt)
                track_syn_flood(pkt)
                track_brute_force(pkt)
                finished_key = ingest(pkt)

                if finished_key:
                    process_flow(finished_key, model, anomaly_detector)

                if time.time() - last_expiry_check > 5:  # 5 seconds for fast testing
                    for key in check_expired_flows():
                        process_flow(key, model, anomaly_detector)
                    last_expiry_check = time.time()

    except KeyboardInterrupt:
        log.info("\nShutting down — flushing remaining flows...")


if __name__ == "__main__":
    main()
