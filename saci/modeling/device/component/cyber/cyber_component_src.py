from pathlib import Path

from saci.modeling.device.component.cyber.cyber_component_base import CyberComponentBase
from saci.modeling.device.component.cyber.cyber_abstraction_level import CyberAbstractionLevel


class CyberComponentSourceCode(CyberComponentBase):
    __state_slots__ = CyberComponentBase.__state_slots__ + ("current_line",)
    __slots__ = CyberComponentBase.__slots__ + (
        "source_root",
        "current_line",
    )

    def __init__(
        self,
        source_root: Path | None = None,
        current_line: int | None = None,
        abstraction=CyberAbstractionLevel.SOURCE,
        **kwargs,
    ):
        super().__init__(abstraction=abstraction, **kwargs)
        self.source_root = source_root

        self.current_line = current_line
