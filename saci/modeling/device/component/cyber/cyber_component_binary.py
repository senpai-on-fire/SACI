from pathlib import Path

from saci.modeling.device.component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from saci.modeling.device.component.cyber.cyber_component_base import CyberComponentBase


class CyberComponentBinary(CyberComponentBase):
    __state_slots__ = CyberComponentBase.__state_slots__ + ("pc",)
    __slots__ = CyberComponentBase.__slots__ + (
        "binary_path",
        "pc",
    )

    def __init__(
        self,
        binary_path: Path | None = None,
        pc: int | None = None,
        abstraction=CyberAbstractionLevel.BINARY,
        **kwargs,
    ):
        super().__init__(abstraction=abstraction, **kwargs)
        self.binary_path = binary_path

        self.pc = pc
