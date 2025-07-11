# ID Manipulation Detection and Countermeasure Module for AngelNET (Enhanced)

import hashlib
import logging
import time
import json
import os
import base64
from typing import Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logging.basicConfig(level=logging.INFO)

# === SECURE ENCRYPTION SETUP ===
ENCRYPTION_KEY = AESGCM.generate_key(bit_length=128)
aesgcm = AESGCM(ENCRYPTION_KEY)

# Simulated ID registry and anomaly logs
ID_REGISTRY: Dict[str, Dict[str, Any]] = {}
ANOMALY_LOG: list = []
BLOCKED_ENTITIES: set = set()

# Thresholds and patterns
MAX_ID_VARIATIONS = 3
ID_FREQUENCY_WINDOW = 60  # seconds
BLOCK_DURATION = 3600  # 1 hour temporary blocks

# Known manipulation patterns (e.g., time drift, char obfuscation, spoofing)
KNOWN_PATTERNS = ["x00", "\u200b", "admin000", "::", "\u0001", "__proto__", "null"]

TEMP_BLOCKS: Dict[str, float] = {}

# === ENCRYPTED LOGGING ===
def encrypt_log(data: dict) -> str:
    nonce = os.urandom(12)
    serialized = json.dumps(data).encode()
    encrypted = aesgcm.encrypt(nonce, serialized, None)
    return base64.b64encode(nonce + encrypted).decode()

def decrypt_log(blob: str) -> dict:
    raw = base64.b64decode(blob)
    nonce, encrypted = raw[:12], raw[12:]
    decrypted = aesgcm.decrypt(nonce, encrypted, None)
    return json.loads(decrypted.decode())

# === REGISTRATION & DETECTION ===
def register_id(user_id: str, fingerprint: str, ip: str) -> bool:
    now = time.time()
    if is_temporarily_blocked(user_id):
        logging.warning(f"[BLOCKED] {user_id} is under temporary block.")
        return True

    if user_id not in ID_REGISTRY:
        ID_REGISTRY[user_id] = {"fingerprints": {fingerprint}, "timestamps": [now], "ips": {ip}}
    else:
        ID_REGISTRY[user_id]["fingerprints"].add(fingerprint)
        ID_REGISTRY[user_id]["timestamps"].append(now)
        ID_REGISTRY[user_id]["ips"].add(ip)

    return detect_anomalies(user_id)

def detect_anomalies(user_id: str) -> bool:
    record = ID_REGISTRY.get(user_id)
    if not record:
        return False

    if len(record["fingerprints"]) > MAX_ID_VARIATIONS:
        flag_and_block(user_id, reason="Too many ID fingerprint variations")
        return True

    recent = [t for t in record["timestamps"] if time.time() - t < ID_FREQUENCY_WINDOW]
    if len(recent) > 10:
        flag_and_block(user_id, reason="High frequency ID reuse")
        return True

    for fp in record["fingerprints"]:
        if any(pat in fp for pat in KNOWN_PATTERNS):
            flag_and_block(user_id, reason="Pattern match ID obfuscation")
            return True

    return False

def flag_and_block(user_id: str, reason: str):
    BLOCKED_ENTITIES.add(user_id)
    TEMP_BLOCKS[user_id] = time.time() + BLOCK_DURATION
    log_data = {"user_id": user_id, "timestamp": time.time(), "reason": reason}
    encrypted = encrypt_log(log_data)
    ANOMALY_LOG.append(encrypted)
    logging.warning(f"[SECURITY] Blocked {user_id}: {reason}")

def is_blocked(user_id: str) -> bool:
    return user_id in BLOCKED_ENTITIES

def is_temporarily_blocked(user_id: str) -> bool:
    if user_id in TEMP_BLOCKS:
        if time.time() < TEMP_BLOCKS[user_id]:
            return True
        else:
            del TEMP_BLOCKS[user_id]
            BLOCKED_ENTITIES.discard(user_id)
    return False

def generate_fingerprint(user_id: str, device_info: str, session_seed: str) -> str:
    raw = f"{user_id}:{device_info}:{session_seed}"
    return hashlib.sha256(raw.encode()).hexdigest()

# === Example Usage ===
if __name__ == "__main__":
    uid = "hyper_user_007"
    device = "bios:vm-667a"
    session = str(time.time())

    fp = generate_fingerprint(uid, device, session)
    status = register_id(uid, fp, ip="192.168.0.4")

    print(f"User '{uid}' status: {'BLOCKED' if is_blocked(uid) else 'ALLOWED'}")

    print("\nDecrypted Anomaly Log:")
    for entry in ANOMALY_LOG:
        print(decrypt_log(entry))
