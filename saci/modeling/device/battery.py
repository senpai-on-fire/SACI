from saci.modeling.device.component import HardwareComponentBase, HardwareAbstractionLevel, HardwareHigh, HardwareCircuit

class BatteryHigh(HardwareHigh):
    __slots__ = HardwareHigh.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

class BatteryCircuit(HardwareCircuit): 
    __slots__ = HardwareCircuit.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

class Battery(HardwareComponentBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ABSTRACTIONS = {
            HardwareAbstractionLevel.HIGH: BatteryHigh(),
            HardwareAbstractionLevel.CIRCUIT: BatteryCircuit(),
        }
