from dataclasses import dataclass

from ..device import ComponentBase
from ..device.device import ComponentID


@dataclass(frozen=True)
class GlobalState:
    components: dict[ComponentID, ComponentBase]
    time: int = 0
