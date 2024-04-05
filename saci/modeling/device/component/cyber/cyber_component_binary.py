from typing import Optional
from pathlib import Path

from saci.modeling.device.component.cyber.cyber_component_base import CyberComponentBase
from saci.modeling.device.component.cyber.cyber_abstraction_level import CyberAbstractionLevel


class CyberComponentBinary(CyberComponentBase):
    __state_slots__ = CyberComponentBase.__state_slots__ + ("pc",)
    __slots__ = CyberComponentBase.__slots__ + ("binary_path", "pc",)

    def __init__(
        self,
        binary_path: Path = None,
        pc: Optional[int] = None,
        abstraction=CyberAbstractionLevel.BINARY,
        **kwargs,
    ):
        super().__init__(abstraction=abstraction, **kwargs)
        self.binary_path = binary_path

        self.pc = pc
