from pydantic import BaseModel

import saci.webui.web_models as model


class ConnectionItem(BaseModel):
    """Represents a data item within a Port Connection."""

    id: int | None = None
    name: str
    units: str | None = None


class Connection(BaseModel):
    """Defines a connection within a Port, linking to a Signal representation format."""

    id: int | None = None
    name: str
    items: dict[  # Dictionary mapping signal names to their metadata
        str, ConnectionItem
    ]
    params: dict[  # Configuration parameters for the connection
        str, str | float | int
    ] = {}


class Port(BaseModel):
    """Represents an input/output element for a System."""

    id: int | None = None
    name: str
    connections: dict[  # Connections represent multiple Signal formats
        str, Connection
    ] = {}
    unique_instance_id: str | None = None


class Interface(BaseModel):
    """Establishes a connection between two Ports and handles Signal format conversions."""

    id: int | None = None
    conversions: dict[str, dict[str, str | None]] = {}  # Mapping of format conversions
    src_port: Port
    dest_port: Port

    def to_saci_connection(self) -> tuple[model.ComponentID, model.ComponentID]:
        """Convert the Interface to a connection tuple for SACI."""
        return (
            model.ComponentID(self.src_port.name),
            model.ComponentID(self.dest_port.name),
        )


class Action(BaseModel):
    """Defines a simulation procedure for a System."""

    ports: dict[str, Port]  # Mapping of port names to Port instances
    function_ref: str  # Reference to the simulator function for execution


class Artifact(BaseModel):
    """Represents stored data files related to a System."""

    id: int | None = None
    name: str
    path: str
    filetype: str | None = None
    content: str
    comments: str | None = ""


class Component(BaseModel):
    """Encapsulates data required for configuring a System or sub-System."""

    id: int | None = None
    name: str
    data: dict[  # Free-form data customized per System
        str, str | int | float | list[str]
    ]


class System(BaseModel):
    """A functional block representing a cyber-physical unit in the blueprint."""

    id: int | None = None
    name: str
    saciType: str | None  # This may be out of date per the documentation
    systems: list["System"] = []  # Recursive definition for sub-Systems
    ports: list[Port] = []
    interfaces: list[Interface] = []
    actions: dict[str, Action] = {}  # Dictionary of Actions mapped by their names
    components: list[Component] = []  # Stores configuration data for Project conversion
    artifacts: list[Artifact] = []

    def to_saci_component(self) -> model.ComponentModel:
        """Convert the System to a Component object. Should only be called on
        second-level Systems.
        """
        paramaters = {}

        # TODO: figure out what goes in parameters

        return model.ComponentModel(
            name=self.name,
            parameters=paramaters,
        )


class Blueprint(BaseModel):
    """Top-level structure representing a project blueprint."""

    id: int | None = None
    name: str
    saciType: str | None
    systems: list[System] = []

    def to_saci_device(self) -> model.DeviceModel:
        """Convert the Blueprint to a Device object."""

        components = {
            model.ComponentID(system.name): system.to_saci_component()
            for system in self.systems
        }

        interfaces = [
            (
                model.ComponentID(interface.src_port.name),
                model.ComponentID(interface.dest_port.name),
            )
            for system in self.systems
            for interface in system.interfaces
        ]

        return model.DeviceModel(
            name=self.name,
            components=components,
            connections=interfaces,
            hypotheses={},  # Hypotheses are not included in the Blueprint
            annotations={},  # Annotations are not included in the Blueprint, unsure how to map
        )


if __name__ == "__main__":
    import json
    import sys

    file = sys.argv[1]
    with open(file) as f:
        data = json.load(f)
        blueprint = Blueprint(**data)

    device = blueprint.to_saci_device()

    # Add example of converting and saving to database
    from saci.webui.db import get_session, init_db, get_engine, Device

    # Initialize DB if needed
    engine = get_engine()
    init_db(engine)
    session = get_session(engine)

    # Convert the blueprint and save to DB
    device = Device.from_web_model(
        device, device_id=str(blueprint.id) if blueprint.id else None
    )
    print(f"Saved blueprint as device with ID: {device.id}")
