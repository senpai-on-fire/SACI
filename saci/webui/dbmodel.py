from sqlmodel import SQLModel

from saci.modeling.device import ComponentID


class ComponentModel(SQLModel, table=True):
    name: str
    type_: str
    parameters: dict[str, str]


class HypothesisModel(SQLModel, table=True):
    name: str
    entry_component: ComponentID | None
    exit_component: ComponentID | None


HypothesisID = str


class DeviceModel(SQLModel, table=True):
    name: str
    components: dict[ComponentID, ComponentModel]
    connections: list[tuple[ComponentID, ComponentID]]
    hypotheses: dict[HypothesisID, HypothesisModel]
