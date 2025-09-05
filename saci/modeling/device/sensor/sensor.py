from ..component import CyberAbstractionLevel, CyberComponentAlgorithmic, CyberComponentBase, CyberComponentHigh


class SensorHigh(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__ + ("variables",)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # For a high-level abstraction, you might store
        # very coarse information or aggregated data.
        # e.g. status, operational mode, or aggregated readings
        self.variables = {}
        # self.variables["status"] = BVS("sensor_status", 8)  # example


class SensorAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__ + ("variables",)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Example symbolic variables for the sensor:
        self.variables = {}
        # self.variables["reading"] = BVS("sensor_reading", 32)
        # self.variables["sampling_rate"] = BVS("sensor_sampling_rate", 32)
        # self.variables["noise_level"] = BVS("sensor_noise_level", 32)
        # self.variables["range_min"] = BVS("sensor_range_min", 32)
        # self.variables["range_max"] = BVS("sensor_range_max", 32)
        # self.variables["resolution"] = BVS("sensor_resolution", 32)
        # self.variables["units"] = BVS("sensor_units", 32)  # might not need to be symbolic


class Sensor(CyberComponentBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: SensorHigh(),
            CyberAbstractionLevel.ALGORITHMIC: SensorAlgorithmic(),
        }
