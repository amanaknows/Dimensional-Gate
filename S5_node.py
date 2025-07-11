# AngelNET S5 Node - Secure Attack Proxy with Quantum Discovery, Synthetic Delivery, and Env Defense

from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib, logging, time, os, base64, json, hmac, random
import asyncio, datetime, platform, socket

# === SETUP ===
app = FastAPI(title="AngelNET S5 Quantum Node")
security = HTTPBearer()
logging.basicConfig(level=logging.INFO)

# === SECURE KEYS ===
NODE_AES_KEY = AESGCM.generate_key(bit_length=128)
aesgcm = AESGCM(NODE_AES_KEY)
HMAC_SECRET = b"ultrasafe-hmac-secure"

# === DATA STORES ===
BADGE_STORE, ACCESS_LOG = {}, []
BLACKLIST, WHITELIST, ANOMALY_EVENTS = set(), set(), []
REPUTATION_SCORE, ENV_SNAPSHOT = {}, {}
ENTITY_BLACKLIST, SIGNAL_DENYLIST = set(), set()
ALLOWED_CLEARANCE = {"A", "AA", "AAA", "SS", "S"}  # exclude S3
USER_CLEARANCE = {
    "hyper_admin": "AAA",
    "attack_operator_001": "AA",
    "hyper_user_001": "A",
    "experimental_entity_007": "X",
    "angelnet_legacy_S3": "S3"
}

# === POLICY & ENV ===
POLICY_VERSION = 1
CURRENT_POLICY = {"max_conn": 100, "allowed_verses": ["*"]}
TIME_ENV = {
    "timestamp": time.time(),
    "datetime": str(datetime.datetime.now()),
    "timezone": time.tzname,
    "os": platform.system(),
    "hostname": socket.gethostname()
}

# === CLASSES ===
class AccessRequest(BaseModel): user_id: str; badge_hash: str; verse_tag: str
class ResonanceData(BaseModel): user_id: str; badge_hash: str; waveform_compressed: bytes; timestamp: float
class SignedMessage(BaseModel): nonce: str; ciphertext: str; signature: str

# === SECURITY FUNCTIONS ===
def generate_badge(user_id, sig):
    badge = hashlib.sha256(f"{user_id}:{sig}".encode()).hexdigest()
    BADGE_STORE[user_id] = badge
    return badge

def verify_badge(user_id, badge):
    return BADGE_STORE.get(user_id) == badge

def is_blacklisted(uid): return uid in BLACKLIST

def get_clearance(user_id):
    return USER_CLEARANCE.get(user_id, None)

def check_clearance(user_id):
    clearance = get_clearance(user_id)
    return clearance in ALLOWED_CLEARANCE

def sign_message(msg: bytes):
    return base64.b64encode(hmac.new(HMAC_SECRET, msg, hashlib.sha256).digest()).decode()

def verify_signature(msg: bytes, sig_b64: str):
    return hmac.compare_digest(base64.b64decode(sig_b64), hmac.new(HMAC_SECRET, msg, hashlib.sha256).digest())

def encrypt_msg(plain: bytes, nonce: bytes): return aesgcm.encrypt(nonce, plain, None)

def decrypt_msg(cipher: bytes, nonce: bytes): return aesgcm.decrypt(nonce, cipher, None)

def analyze_waveform(wave: bytes) -> bool:
    h = hashlib.sha256(wave).hexdigest()
    return h in SIGNAL_DENYLIST or h.startswith("dead") or wave.count(b'\x00') > 50

def collapse_env():
    logging.critical("ENV COLLAPSE TRIGGERED")
    os._exit(1)

async def auto_instance_check():
    try:
        await asyncio.sleep(0.1)
        logging.info("Connecting to: FresnoDisk, FireflyChain, AngelNET...")
        return True
    except Exception:
        collapse_env()

# === API ENDPOINTS ===
@app.post("/generate_badge")
async def api_generate_badge(user_id: str, neural_signature: str):
    return {"user_id": user_id, "badge": generate_badge(user_id, neural_signature)}

@app.post("/request_access")
async def api_request_access(req: AccessRequest):
    if is_blacklisted(req.user_id) or not verify_badge(req.user_id, req.badge_hash):
        raise HTTPException(status_code=403, detail="Access denied")
    if not check_clearance(req.user_id):
        raise HTTPException(status_code=403, detail="Insufficient AngelNET clearance level")
    ACCESS_LOG.append({"uid": req.user_id, "ts": time.time(), "vt": req.verse_tag})
    return {"access_granted": True}

@app.post("/submit_resonance")
async def api_submit_resonance(res: ResonanceData):
    if is_blacklisted(res.user_id):
        raise HTTPException(status_code=403, detail="User is blacklisted")
    if not check_clearance(res.user_id):
        raise HTTPException(status_code=403, detail="Insufficient AngelNET clearance level")
    waveform = base64.b64decode(res.waveform_compressed)
    if analyze_waveform(waveform):
        raise HTTPException(status_code=403, detail="Malicious waveform detected")
    REPUTATION_SCORE[res.user_id] = REPUTATION_SCORE.get(res.user_id, 1.0) - 0.1
    return {"status": "waveform accepted"}

@app.post("/sync_policy")
async def node_sync_policy(signed_msg: SignedMessage):
    nonce = base64.b64decode(signed_msg.nonce)
    cipher = base64.b64decode(signed_msg.ciphertext)
    if not verify_signature(signed_msg.nonce.encode() + signed_msg.ciphertext.encode(), signed_msg.signature):
        raise HTTPException(status_code=403, detail="Invalid signature")
    policy_update = json.loads(decrypt_msg(cipher, nonce).decode())
    global CURRENT_POLICY, POLICY_VERSION
    CURRENT_POLICY = policy_update; POLICY_VERSION += 1
    return {"policy_version": POLICY_VERSION, "status": "updated"}

@app.get("/status")
async def api_status():
    return {
        "status": "Online", 
        "policy_version": POLICY_VERSION, 
        "timestamp": TIME_ENV["timestamp"],
        "env": TIME_ENV
    }

# === STARTUP ===
@app.on_event("startup")
async def startup_event():
    await auto_instance_check()
    logging.info("AngelNET S5 Node boot complete.")
