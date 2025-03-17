from collections.abc import Hashable
from dataclasses import dataclass
from typing_extensions import Generic, TypeVar

from ..device.componentid import ComponentID
from ..device import ComponentBase


CID = TypeVar('CID', bound=Hashable)

@dataclass(frozen=True)
class GlobalState(Generic[CID]):
    components: dict[CID, ComponentBase]
    time: int = 0
