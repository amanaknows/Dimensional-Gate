import numpy as np
import time
import threading

class SensorAdapter:
    """
    Simulates or interfaces with real sensors.
    Supports live streaming, buffering, and normalization.
    """

    def __init__(self, sensor_type="simulated", sample_rate=1000, buffer_size=1024):
        self.sensor_type = sensor_type
        self.sample_rate = sample_rate
        self.buffer_size = buffer_size
        self.buffer = np.zeros(buffer_size, dtype=np.float32)
        self.running = False
        self.lock = threading.Lock()
        self.thread = None

    def _simulate_sensor_data(self):
        """
        Generates synthetic sensor data - can be replaced by real sensor input.
        """
        while self.running:
            new_sample = np.sin(2 * np.pi * 440 * time.time())  # 440 Hz tone example
            with self.lock:
                self.buffer = np.roll(self.buffer, -1)
                self.buffer[-1] = new_sample
            time.sleep(1 / self.sample_rate)

    def start_stream(self):
        if self.sensor_type == "simulated":
            self.running = True
            self.thread = threading.Thread(target=self._simulate_sensor_data)
            self.thread.start()

    def stop_stream(self):
        self.running = False
        if self.thread:
            self.thread.join()

    def read_buffer(self):
        with self.lock:
            return np.copy(self.buffer)

    def normalize(self, data):
        max_val = np.max(np.abs(data))
        return data / max_val if max_val > 0 else data
