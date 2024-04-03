from typing import List, Optional
from pathlib import Path

from .component_base import ComponentBase
from .cyber_abstraction_level import CyberAbstractionLevel


class ComponentSourceCode(ComponentBase):
    __state_slots__ = ComponentBase.__state_slots__ + ("current_line", )
    __slots__ = ComponentBase.__slots__ + ("source_root", "current_line", )

    def __init__(
        self,
        source_root: Path = None,
        current_line: Optional[int] = None,
        abstraction=CyberAbstractionLevel.SOURCE,
        **kwargs,
    ):
        super().__init__(abstraction=abstraction, **kwargs)
        self.source_root = source_root

        self.current_line = current_line
