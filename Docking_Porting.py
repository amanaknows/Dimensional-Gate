import numpy as np
import uuid
import logging
import hashlib
from scipy.fftpack import fft, ifft

logging.basicConfig(level=logging.INFO)

# ------------------ Foundational Constants ------------------
PLANCK_CONSTANT = 6.626e-34
SPEED_OF_LIGHT = 3e8
SOUND_SPEED = 343  # m/s in air

# ------------------ Waveform Generator ------------------

class Waveform:
    def __init__(self, freq, amp, duration, source_type="unknown"):
        self.freq = freq
        self.amp = amp
        self.duration = duration
        self.source_type = source_type
        self.id = uuid.uuid4().hex
        self.signal = self._generate()
        logging.info(f"Waveform [{self.id[:6]}]: {source_type} waveform created @ {freq}Hz")

    def _generate(self):
        t = np.linspace(0, self.duration, int(self.duration * 1000))
        return self.amp * np.sin(2 * np.pi * self.freq * t)

    def quantize(self):
        return np.round(self.signal, 5)

    def spectrum(self):
        return np.abs(fft(self.signal))

# ------------------ Light ↔ Matter Converter ------------------

class LightMatterTransmuter:
    def to_matter(self, waveform):
        energy = PLANCK_CONSTANT * waveform.freq
        mass = energy / (SPEED_OF_LIGHT ** 2)
        logging.info(f"Light → Matter: Frequency {waveform.freq}Hz -> Mass ≈ {mass:.6e} kg")
        return {"mass": mass, "id": waveform.id, "type": "photonic_matter"}

    def to_light(self, mass):
        energy = mass * (SPEED_OF_LIGHT ** 2)
        freq = energy / PLANCK_CONSTANT
        logging.info(f"Matter → Light: Mass {mass}kg -> Frequency ≈ {freq:.2e} Hz")
        return freq

# ------------------ Sound ↔ Matter Converter ------------------

class SoundMatterTransmuter:
    def to_matter(self, waveform):
        # Sound → Matter (symbolic: density of waveform used as proxy)
        density = np.mean(np.abs(waveform.signal))
        mass = density * 1e-6  # arbitrary scale
        logging.info(f"Sound → Matter: Waveform density {density:.3f} -> Mass ≈ {mass:.6e} kg")
        return {"mass": mass, "id": waveform.id, "type": "sonic_matter"}

    def to_sound(self, mass):
        freq = np.sqrt(mass * 1e6) * 10  # reverse-engineered dummy equation
        logging.info(f"Matter → Sound: Mass {mass}kg -> Frequency ≈ {freq:.2f} Hz")
        return freq

# ------------------ Waveform Classifier ------------------

class VersalClassifier:
    def classify(self, waveform):
        spectrum = waveform.spectrum()
        centroid = np.mean(spectrum)
        hashval = hashlib.sha256(waveform.signal).hexdigest()[:8]

        if centroid > 5000:
            realm = "metaversal"
        elif centroid > 500:
            realm = "versal"
        else:
            realm = "sub-versal"

        logging.info(f"Waveform [{waveform.id[:6]}] classified as {realm.upper()} [{hashval}]")
        return {
            "id": waveform.id,
            "realm": realm,
            "centroid": centroid,
            "hash": hashval
        }

# ------------------ Docking & Porting ------------------

class MultiVersalPort:
    def __init__(self):
        self.ports = {}

    def dock(self, waveform, location="universe_alpha"):
        port_id = uuid.uuid4().hex
        self.ports[port_id] = {
            "waveform": waveform,
            "realm": location
        }
        logging.info(f"Docked waveform [{waveform.id[:6]}] to realm '{location}' via port [{port_id[:6]}]")
        return port_id

    def transmit(self, port_id, new_realm):
        if port_id in self.ports:
            self.ports[port_id]['realm'] = new_realm
            logging.info(f"Transmitted waveform [{self.ports[port_id]['waveform'].id[:6]}] → {new_realm}")
        else:
            logging.warning(f"Port ID [{port_id[:6]_]()
