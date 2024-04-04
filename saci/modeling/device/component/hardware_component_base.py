from typing import Tuple, List

from .cyber_abstraction_level import CyberAbstractionLevel
from .component_base import ComponentBase
from .component_type import ComponentType
from ...communication.base_comm import BaseCommunication


class HardwareComponentBase(ComponentBase):
    """
    A CyberComponentBase is the base class for all components in the system. A component, at a high-level, is any device
    in the full system that can talk to at least one other device.
    """
    __state_slots__ = ComponentBase.__state_slots__ + ()
    __slots__ = ComponentBase.__slots__ + ("abstraction_level",)

    def __init__(self, name=None, _type=ComponentType.HARDWARE, abstraction=None):
        super().__init__(nam=name, _type=_type)
        self.abstraction_level = abstraction