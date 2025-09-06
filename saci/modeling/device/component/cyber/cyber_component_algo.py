# TODO: maybe dont bind to z3
import claripy

from saci.modeling.device.component.cyber.cyber_abstraction_level import CyberAbstractionLevel
from saci.modeling.device.component.cyber.cyber_component_base import CyberComponentBase


class CyberComponentAlgorithmic(CyberComponentBase):
    __state_slots__ = CyberComponentBase.__state_slots__ + ("conditions",)
    __slots__ = CyberComponentBase.__slots__ + (
        "conditions",
        "variables",
    )

    def __init__(
        self,
        abstraction=CyberAbstractionLevel.ALGORITHMIC,
        variables: dict[str, claripy.ast.bv.BV] | None = None,
        conditions: list[claripy.ast.bool.Bool] | None = None,
        **kwargs,
    ):
        super().__init__(abstraction=abstraction, **kwargs)
        self.variables = variables or {}

        self.conditions = conditions or []

    @property
    def v(self):
        return self.variables
