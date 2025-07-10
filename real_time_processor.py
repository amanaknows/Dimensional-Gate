import time
from sensor_adapter import SensorAdapter
from your_core_module import SignalProcessor, SignalToRealityGateway, AngelNetMemoryMatrix, AdaptiveOracle  # Replace with actual import path

class RealTimeSignalProcessor:
    def __init__(self, sensor_adapter, signal_processor, gateway, processing_interval=0.1):
        self.sensor = sensor_adapter
        self.processor = signal_processor
        self.gateway = gateway
        self.processing_interval = processing_interval  # seconds
        self.running = False

    def process_loop(self, user_features):
        self.sensor.start_stream()
        self.running = True
        try:
            while self.running:
                raw_data = self.sensor.read_buffer()
                normalized = self.sensor.normalize(raw_data)
                dominant_freq = self.processor.dominant_freq(normalized)
                tag, signature = self.gateway.enter_door_one(normalized, user_features)
                if tag:
                    self.gateway.enter_door_two(tag, user_features)
                time.sleep(self.processing_interval)
        finally:
            self.sensor.stop_stream()

    def stop(self):
        self.running = False

# Usage Example:
# sensor_adapter = SensorAdapter()
# signal_processor = SignalProcessor()
# matrix = AngelNetMemoryMatrix()
# oracle = AdaptiveOracle()
# gateway = SignalToRealityGateway(matrix, oracle, signal_processor)
# realtime_processor = RealTimeSignalProcessor(sensor_adapter, signal_processor, gateway)
# realtime_processor.process_loop(user_features=[...])
