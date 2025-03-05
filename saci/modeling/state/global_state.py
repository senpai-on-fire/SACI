from dataclasses import dataclass
from typing import List

from ..device.componentid import ComponentID
from ..device import ComponentBase


@dataclass(frozen=True)
class GlobalState:
    components: dict[ComponentID, ComponentBase]
    time: int = 0
