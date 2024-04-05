from typing import Tuple, List

from saci.modeling.device.component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from saci.modeling.device.component.component_base import ComponentBase
from saci.modeling.device.component.component_type import ComponentType
from saci.modeling.communication.base_comm import BaseCommunication


class CyberComponentBase(ComponentBase):
    """
    A CyberComponentBase is the base class for all components in the system. A component, at a high-level, is any device
    in the full system that can talk to at least one other device.
    """
    __state_slots__ = ComponentBase.__state_slots__ + ()
    __slots__ = ComponentBase.__slots__ + ("abstraction_level",)

    def __init__(self, name=None, _type=ComponentType.CYBER, abstraction=CyberAbstractionLevel.UNKNOWN):
        super().__init__(name=name, _type=_type)
        self.abstraction_level = abstraction

    #
    # Simulation Useful Functions
    #

    def state_update(self, source: "CyberComponentBase", data: BaseCommunication) -> List["CyberComponentBase"]:
        """
        A State Update function describes how a component's state changes when it receives data from another component.
        Given a source component and data, the function should return a new component (of the same type as self) with
        the updated state.

        :param source:
        :param data:
        :return:
        """
        raise NotImplementedError

    def inverse_state_update(self, state: "CyberComponentBase") -> List[Tuple["CyberComponentBase", BaseCommunication]]:
        """
        An Inverse State Update function describes what possible inputs could have caused the provided state.
        The possible inputs are a list of

        :param state:
        :return:
        """
        raise NotImplementedError

    def copy(self) -> "CyberComponentBase":
        """
        Copy the component
        """
        new_comp = self.__class__()
        for attr in self.__slots__:
            setattr(new_comp, attr.copy() if attr else None, getattr(self, attr))

        return new_comp
