from pydantic import BaseModel

import saci.webui.db as db


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
    unique_instance_id: str


class Interface(BaseModel):
    """Establishes a connection between two Ports and handles Signal format conversions."""

    id: int | None = None
    conversions: dict[str, dict[str, str | None]] = {}  # Mapping of format conversions
    src_port: Port
    dest_port: Port


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


class Specification(BaseModel):
    """A specific value of something associated with a system."""

    id: int | None = None
    name: str
    value: str | int | float
    units: str
    comments: str | None = None


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
    specifications: list[Specification] = []

    def collect_ports(self) -> dict[str, int]:
        """Collect a mapping of each port's unique_instance_id to its System's identity, for this system and all its
        subsystems.

        NB: the system's "identity" is `id(system)`, not `system.id`, in order to support cases where no `id` field
        value is supplied in the blueprint.

        """
        port_to_system = {}

        for sub in self.systems:
            port_to_system |= sub.collect_ports()

        for port in self.ports:
            port_to_system[port.unique_instance_id] = id(self)

        return port_to_system

    def collect_db_components(self) -> dict[int, db.Component]:
        """Collect a mapping of each system's identity to a newly-created db.Component with its data.

        NB: same identity as documented in System.collect_ports.

        """
        system_to_component = {}

        for sub in self.systems:
            system_to_component |= sub.collect_db_components()

        # TODO: flesh out our notion of parameters
        parameters = {spec.name: str(spec.value) for spec in self.specifications}
        system_to_component[id(self)] = db.Component(name=self.name, type_=self.saciType, parameters=parameters, is_entry=False)

        return system_to_component

    def collect_db_connections(self, port_to_system: dict[str, int], system_to_component: dict[int, db.Component]) -> list[db.Connection]:
        """Collect a list of connections between components, based on all the systems' interfaces.

        Assumes port_to_system and system_to_component have been generated according to System.collect_ports and
        System.collect_db_components respectively, on the whole system.

        """
        connections = []

        for sub in self.systems:
            connections += sub.collect_db_connections(port_to_system, system_to_component)

        for interface in self.interfaces:
            connections.append(db.Connection(
                from_component=system_to_component[port_to_system[interface.src_port.unique_instance_id]],
                to_component=system_to_component[port_to_system[interface.dest_port.unique_instance_id]],
            ))

        return connections

    def to_db_device(self, device_id: str) -> db.Device:
        """Turn this top-level system into a db.Device, collecting all of the subsystems and connections between them."""

        # I think these three steps could be done all in one pass, assuming a blueprint's interfaces are well-scoped,
        # but I think it's clearer this way and blueprints will be small (< 1000 subsystems), so I wrote it like this
        # instead.
        
        # First collect port-to-system mapping
        port_to_system = self.collect_ports()

        # Second collect system identity-to-db.Component mapping
        #
        # NB: use `id(system)`, not `system.id`, as documented in System.collect_ports
        system_to_component = self.collect_db_components()

        # Third collect connections from all interfaces
        connections = self.collect_db_connections(port_to_system, system_to_component)

        return db.Device(
            id=device_id,
            name=self.name,
            # TODO: this includes the top-level system. do we want that?
            components=list(system_to_component.values()),
            connections=connections,
            hypotheses=[],
            annotations=[],
        )


if __name__ == "__main__":
    import json
    import sys

    file = sys.argv[1]
    with open(file) as f:
        data = json.load(f)
        blueprint = System(**data)

    # Convert the blueprint to a db.Device
    device_id = sys.argv[2] if len(sys.argv) >= 3 else blueprint.name
    device = blueprint.to_db_device(device_id)

    # Add example of converting and saving to database
    from saci.webui.db import get_session, init_db, get_engine, Device

    # Initialize DB if needed
    engine = get_engine()
    init_db(engine)
    session = get_session(engine)

    # Save the device to DB
    session.add(device)
    session.commit()
