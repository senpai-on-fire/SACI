from typing import Optional, Type, Iterator, Tuple

from ..modeling import CyberAbstractionLevel, ComponentType, ComponentBase
from .base_constrainer import BaseConstrainer
from .binary_constrainer import BinaryConstrainer
from .c_constrainer import CConstrainer
from .fsm_constrainer import FSMConstrainer
from .bruteforce_constrainer import BruteforceConstrainer
from .cyber_high_constrainer import CyberHighConstrainer
from .telemetry_high_constrainer import TelemetryHighConstrainer
from .actuator_high_constrainer import ActuatorHighConstrainer


CONSTRAINERS = {
    ComponentType.CYBER: {
        CyberAbstractionLevel.HIGH: [CyberHighConstrainer, TelemetryHighConstrainer, ActuatorHighConstrainer],
        CyberAbstractionLevel.ALGORITHMIC: [FSMConstrainer, BruteforceConstrainer],
        CyberAbstractionLevel.SOURCE: [CConstrainer, BruteforceConstrainer],
        CyberAbstractionLevel.BINARY: [BinaryConstrainer, BruteforceConstrainer],
    },
    ComponentType.HARDWARE: {

    }
}


def get_constrainer_and_abstract_component(component: ComponentBase) -> Iterator[Tuple[Type[BaseConstrainer], ComponentBase]]:
    # the component must be a combo class (with abstractions)
    assert hasattr(component, "ABSTRACTIONS")
    for level, abs_obj in component.ABSTRACTIONS.items():
        for constrainer_cls in get_constrainer(abs_obj):
            yield constrainer_cls, abs_obj


def get_constrainer(component: ComponentBase) -> Iterator[Type[BaseConstrainer]]:
    if component.type in CONSTRAINERS:
        # the component must be a single component
        assert not hasattr(component, "ABSTRACTIONS")

        if component.abstraction_level in CONSTRAINERS[component.type]:
            for constrainer_cls in CONSTRAINERS[component.type][component.abstraction_level]:
                if constrainer_cls.supports(component):
                    yield constrainer_cls
