from typing import Optional, Type, Iterator

from ..modeling import CyberAbstractionLevel, ComponentType, ComponentBase
from .base_constrainer import BaseConstrainer
from .binary_constrainer import BinaryConstrainer
from .c_constrainer import CConstrainer
from .fsm_constrainer import FSMConstrainer
from .bruteforce_constrainer import BruteforceConstrainer


CONSTRAINERS = {
    ComponentType.CYBER: {
        CyberAbstractionLevel.ALGORITHMIC: [FSMConstrainer, BruteforceConstrainer],
        CyberAbstractionLevel.SOURCE: [CConstrainer, BruteforceConstrainer],
        CyberAbstractionLevel.BINARY: [BinaryConstrainer, BruteforceConstrainer],
    },
    ComponentType.HARDWARE: {

    }
}


def get_constrainer(component: ComponentBase) -> Iterator[Type[BaseConstrainer]]:
    if component.type in CONSTRAINERS:
        if component.abstraction_level in CONSTRAINERS[component.type]:
            for constrainer_cls in CONSTRAINERS[component.type][component.abstraction_level]:
                if constrainer_cls.supports(component):
                    yield constrainer_cls
