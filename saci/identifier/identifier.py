from typing import List, Optional, Dict, Type, Any

from ..modeling import Device, CPV


class Identifier:
    def __init__(self, device: Device, cpvs: List[CPV]):
        self.device = device
        self.cpvs = cpvs

    def identify(self) -> Dict[Type[CPV], List]:
        return {}
