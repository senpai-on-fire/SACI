from .cyber_component_base import CyberComponentBase
from .cyber_abstraction_level import CyberAbstractionLevel


class CyberComponentHigh(CyberComponentBase):
    __state_slots__ = CyberComponentBase.__state_slots__ + ("powered",)
    __slots__ = CyberComponentBase.__slots__ + ("powered", "has_external_input")

    def __init__(self, abstraction=CyberAbstractionLevel.HIGH, powered=True, has_external_input=False, **kwargs):
        super().__init__(abstraction=abstraction, **kwargs)
        self.has_external_input = has_external_input

        self.powered = powered

