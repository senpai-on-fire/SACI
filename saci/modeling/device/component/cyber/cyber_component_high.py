from saci.modeling.device.component.cyber.cyber_component_base import CyberComponentBase
from saci.modeling.device.component.cyber.cyber_abstraction_level import CyberAbstractionLevel


class CyberComponentHigh(CyberComponentBase):
    __state_slots__ = CyberComponentBase.__state_slots__ + ("powered",)
    __slots__ = CyberComponentBase.__slots__ + ("powered",)

    def __init__(self, abstraction=CyberAbstractionLevel.HIGH, powered=True, **kwargs):
        super().__init__(abstraction=abstraction, **kwargs)

        self.powered = powered

