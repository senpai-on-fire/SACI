from saci.modeling.device.component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from saci.modeling.device.component.component_base import ComponentBase
from saci.modeling.device.component.component_type import ComponentType


class CyberComponentBase(ComponentBase):
    """
    A CyberComponentBase is the base class for all components in the system. A component, at a high-level, is any device
    in the full system that can talk to at least one other device.
    """

    __state_slots__ = ComponentBase.__state_slots__ + ()
    __slots__ = ComponentBase.__slots__ + ("abstraction_level",)

    def __init__(
        self,
        name=None,
        _type=ComponentType.CYBER,
        abstraction=CyberAbstractionLevel.UNKNOWN,
        parameters=None,
        ports=None,
        capabilities=None,
    ):
        super().__init__(name=name, _type=_type, parameters=parameters, ports=ports, capabilities=capabilities)
        self.abstraction_level = abstraction
