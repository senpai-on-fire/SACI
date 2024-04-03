from typing import List, Optional
from pathlib import Path

from .component_base import ComponentBase
from .cyber_abstraction_level import CyberAbstractionLevel


class ComponentBinary(ComponentBase):
    __state_slots__ = ComponentBase.__state_slots__ + ("pc", )
    __slots__ = ComponentBase.__slots__ + ("binary_path", "pc", )

    def __init__(
        self,
        binary_path: Path = None,
        pc: Optional[int] = None,
        abstraction=CyberAbstractionLevel.SOURCE,
        **kwargs,
    ):
        super().__init__(abstraction=abstraction, **kwargs)
        self.binary_path = binary_path

        self.pc = pc
