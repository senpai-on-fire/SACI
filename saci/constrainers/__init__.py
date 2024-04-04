from typing import Optional, Type

from ..modeling import CyberAbstractionLevel, ComponentType
from .base_constrainer import BaseConstrainer
from .binary_constrainer import BinaryConstrainer
from .c_constrainer import CConstrainer
from .fsm_constrainer import FSMConstrainer


CONSTRAINERS = {
    "cyber": {
        "fsm": FSMConstrainer,
        "source": CConstrainer,
        "binary": BinaryConstrainer,
    }
}


def get_constrainer(component) -> Optional[Type[BaseConstrainer]]:
    if component.type in CONSTRAINERS:
        if component.abstraction_layer in CONSTRAINERS[component.type]:
            return CONSTRAINERS[component.type][component.abstraction_layer]
    return None
