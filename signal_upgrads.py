import numpy as np
import hashlib
import logging
import time
import zlib
from scipy.fftpack import fft
from uuid import uuid4
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split

logging.basicConfig(level=logging.INFO)

# -- Signal Capture & FFT Processing --------------------------------------

class SignalProcessor:
    def __init__(self, fs=1000):
        self.fs = fs  # sampling frequency

    def generate_wave(self, freq, duration=1.0):
        t = np.linspace(0, duration, int(self.fs * duration))
        return np.sin(2 * np.pi * freq * t).astype(np.float32)

    def compress_waveform(self, waveform):
        data_bytes = waveform.tobytes()
        compressed = zlib.compress(data_bytes)
        return compressed

    def decompress_waveform(self, compressed_data):
        decompressed = zlib.decompress(compressed_data)
        return np.frombuffer(decompressed, dtype=np.float32)

    def fast_fft(self, waveform):
        return np.abs(fft(waveform))

    def dominant_freq(self, waveform):
        spectrum = self.fast_fft(waveform)
        return np.argmax(spectrum)

# -- Frequency Signature with compression and hashing ----------------------

class FrequencySignature:
    def __init__(self, waveform, processor):
        self.waveform = waveform
        self.processor = processor
        self.compressed_wave = processor.compress_waveform(waveform)
        self.id = uuid4().hex[:8]
        self.dominant_freq = processor.dominant_freq(waveform)
        self.hash = self._hash_signature()
        self.verse_tag = f"verse:{int(self.dominant_freq)}hz"

    def _hash_signature(self):
        return hashlib.sha256(self.compressed_wave).hexdigest()[:16]

    def package(self):
        return {
            "id": self.id,
            "dominant_freq": self.dominant_freq,
            "verse_tag": self.verse_tag,
            "hash": self.hash,
            "waveform_compressed": self.compressed_wave
        }

# -- CryoMemory with temporal smoothing and time-lock ------------------------

class CryoMemoryVault:
    def __init__(self):
        self.vault = {}

    def freeze(self, key, data, unlock_time):
        self.vault[key] = (data, unlock_time)

    def thaw(self, key):
        data, unlock_time = self.vault.get(key, (None, None))
        if data and time.time() >= unlock_time:
            return data
        return None

    def smooth_temporal_bottleneck(self, waveform1, waveform2, alpha=0.5):
        # Simple linear interpolation smoothing between two waveforms
        return alpha * waveform1 + (1 - alpha) * waveform2

# -- Oracle with adaptive ML permission model -------------------------------

class AdaptiveOracle:
    def __init__(self):
        self.label_encoder = LabelEncoder()
        self.classifier = RandomForestClassifier(n_estimators=10)
        self.is_trained = False
        self.training_data = []
        self.training_labels = []

    def add_training_example(self, features, label):
        self.training_data.append(features)
        self.training_labels.append(label)

    def train_model(self):
        if len(self.training_data) < 5:
            logging.warning("Not enough training data yet.")
            return
        X = np.array(self.training_data)
        y = self.label_encoder.fit_transform(self.training_labels)
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
        self.classifier.fit(X_train, y_train)
        acc = self.classifier.score(X_test, y_test)
        logging.info(f"Oracle model trained with accuracy: {acc:.2f}")
        self.is_trained = True

    def evaluate_access(self, features):
        if not self.is_trained:
            logging.warning("Oracle model not trained; denying access.")
            return False
        pred = self.classifier.predict([features])
        label = self.label_encoder.inverse_transform(pred)[0]
        logging.info(f"Oracle predicts access class: {label}")
        # Simplified: grant access if label != 'deny'
        return label != "deny"

# -- Signal to Reality Gateway ----------------------------------------------

class SignalToRealityGateway:
    def __init__(self, matrix, oracle, processor):
        self.matrix = matrix
        self.oracle = oracle
        self.processor = processor

    def enter_door_one(self, signal_wave, user_features):
        sig = FrequencySignature(signal_wave, self.processor)
        tag = sig.verse_tag
        node = self.matrix.reverse_lookup(tag)
        if node:
            allowed = self.oracle.evaluate_access(user_features)
            if allowed:
                logging.info(f"✅ Door One Access Granted to {tag}")
                return tag, sig
            else:
                logging.info(f"❌ Access Denied to {tag}")
                return None, None
        logging.info("⚠️ Unknown Verse Signature")
        return None, None

    def enter_door_two(self, tag, user_features):
        node = self.matrix.reverse_lookup(tag)
        if node:
            allowed = self.oracle.evaluate_access(user_features)
            if allowed:
                logging.info(f"🌀 Portal to {tag} opening...")
                return node
            else:
                logging.info(f"🛑 Door Two Locked for access.")
        else:
            logging.info("🔍 No such verse registered.")
        return None

# -- AngelNet Memory Matrix (as before) -------------------------------------

class AngelNetMemoryMatrix:
    def __init__(self):
        self.encoder = HexagramEncoder()
        self.registry = {}
        self.event_routes = {}

    def tag_and_store(self, coord, frequency_sig):
        addr = self.encoder.encode(coord)
        mnemonic = self.encoder.mnemonic(coord)
        payload = frequency_sig.package()
        payload['mnemonic'] = mnemonic
        self.registry[addr] = payload
        self.event_routes[payload['verse_tag']] = addr
        logging.info(f"[{payload['id']}] Registered at {addr} as {payload['verse_tag']} {mnemonic}")

    def retrieve_by_coord(self, coord):
        return self.registry.get(self.encoder.encode(coord))

    def reverse_lookup(self, verse_tag):
        addr = self.event_routes.get(verse_tag)
        if addr:
            return self.registry[addr]
        return None

# -- Hexagram Encoder & Mnemonic (as before) ---------------------------------

class HexagramEncoder:
    def encode(self, c):
        hash_val = hashlib.sha256(str(c).encode()).hexdigest()[:12]
        return tuple(hash_val[i:i+2] for i in range(0, 12, 2))

    def mnemonic(self, c):
        symbols = ['☉','☽','⚚','☿','♆','♇','⟁','⧉','✶','⛧']
        h = hashlib.md5(str(c).encode()).hexdigest()
        return ''.join([symbols[int(x, 16) % len(symbols)] for x in h[:6]])

# ---------------- Reality Portal Hasher --------------------------------------

def reality_hash_portal(wave, processor):
    sig = FrequencySignature(wave, processor)
    return sig.verse_tag, sig.hash

# ---------------- Frequency Braiding -----------------------------------------

def braid_frequencies(waves):
    return np.sum(waves, axis=0) / len(waves)

# ---------------- Example Usage ----------------------------------------------

if __name__ == "__main__":
    # Setup
    processor = SignalProcessor()
    matrix = AngelNetMemoryMatrix()
    cryo = CryoMemoryVault()
    oracle = AdaptiveOracle()
    gateway = SignalToRealityGateway(matrix, oracle, processor)

    # Generate sample waveforms
    freqs = [432, 528, 963, 777, 888]
    waveforms = [processor.generate_wave(f) for f in freqs]

    # Mandelbrot zoom matrix for tagging
    center = complex(0, 0)
    scale = 0.01
    grid = generate_zoom_matrix(center, scale)

    # Register waveforms in matrix and freeze copies in CryoMemory
    idx = 0
    for row in grid:
        for coord in row:
            if idx < len(waveforms):
                sig = FrequencySignature(waveforms[idx], processor)
                matrix.tag_and_store(coord, sig)
                cryo.freeze(sig.id, sig.package(), time.time() + 10)
                idx += 1

    # Train Oracle with mock data (features could be dominant freq, etc)
    # Format: features=[dominant_freq], label='allow' or 'deny'
    for sig in waveforms:
        dom_freq = processor.dominant_freq(sig)
        oracle.add_training_example([dom_freq], 'allow')
    for freq in [100, 200, 300]:
        oracle.add_training_example([freq], 'deny')
    oracle.train_model()

    # Example user input with real signal
    test_wave = processor.generate_wave(963)
    user_features = [processor.dominant_freq(test_wave)]  # simplified user feature
    tag, signature = gateway.enter_door_one(test_wave, user_features)
    if tag:
        node = gateway.enter_door_two(tag, user_features)

    # Show compressed waveform size savings
    comp_size = len(signature.compressed_wave)
    orig_size = len(signature.waveform) * signature.waveform.itemsize
    logging.info(f"Compressed waveform size: {comp_size} bytes (original {orig_size} bytes)")
