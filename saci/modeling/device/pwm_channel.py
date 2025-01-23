from typing import Optional

from saci.modeling.device.component.component_base import Port, PortDirection, Ports, union_ports
from .component import CyberComponentHigh, CyberComponentBase, HardwareHigh, CyberComponentHigh
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from .component.hardware.hardware_abstraction_level import HardwareAbstractionLevel


class PWMChannelCyberHigh(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__ + ("protection")

    def __init__(self, protection=None, **kwargs):
        super().__init__(**kwargs)
        self.protection = protection

    @property
    def parameter_types(self):
        pass


class PWMChannelHardwareHigh(HardwareHigh):
    __state_slots__ = HardwareHigh.__state_slots__ + ("voltage_level", "duty_cycle", "frequency")
    __slots__ = HardwareHigh.__slots__ + ("voltage_level", "duty_cycle", "frequency")

    def __init__(self, voltage_level=None, duty_cycle=None, frequency=None, **kwargs):
        """
        :param voltage_level:
        :param duty_cycle:
        :param frequency:
        :param kwargs:
        """
        super().__init__(**kwargs)
        # TODO: replace these once we have some concept of state variable
        self.voltage_level = voltage_level
        self.duty_cycle = duty_cycle
        self.frequency = frequency

    @property
    def parameter_types(self):
        return {
            # TODO: How do we know if the controller has integrity check?
            "voltage_level": float,
            "duty_cycle": float,
            "frequency": float,
        }


class PWMChannel(CyberComponentBase):
    def __init__(self, ports: Optional[Ports]=None, **kwargs):
        super().__init__(
            ports=union_ports({
                "Pins": Port(direction=PortDirection.INOUT),
                "Communication": Port(direction=PortDirection.INOUT),
            }, ports),
            **kwargs
        )

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: PWMChannelCyberHigh(**kwargs),
            HardwareAbstractionLevel.HIGH: PWMChannelHardwareHigh(**kwargs),
        }

    @property
    def parameter_types(self):
        pass