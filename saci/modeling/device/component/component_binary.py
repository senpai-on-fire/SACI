from typing import List, Optional
from pathlib import Path

from .component_base import ComponentBase
from .cyber_abstraction_level import CyberAbstractionLevel


class ComponentBinary(ComponentBase):
    STATE_ATTR = ("pc", )

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
