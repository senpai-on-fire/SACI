from __future__ import annotations
import os
from typing import TypeVar

import networkx as nx
from sqlalchemy import (
    Engine,
    String,
    ForeignKey,
    create_engine,
    JSON,
    select,
)
from sqlalchemy.orm import (
    relationship,
    sessionmaker,
    DeclarativeBase,
    Session,
    mapped_column,
    Mapped,
)

from saci.modeling import Device as SaciDevice, ComponentBase as SaciComponent, Annotation as SaciAnnotation
from saci.modeling.capability import Capability as CapabilityEnum
from saci.modeling.device.component.component_base import Port as SaciPort, PortDirection as SaciPortDirection
from saci.hypothesis import Hypothesis as SaciHypothesis
from saci.modeling.vulnerability.base_vuln import MakeEntryEffect, VulnerabilityEffect

# Import web models for conversion methods
from saci.webui.web_models import (
    BlueprintID,
    ComponentModel,
    HypothesisModel,
    AnnotationModel,
    DeviceModel,
    AnnotationID,
)


# Get all component subclasses. We should have a less janky way of doing this.
_T = TypeVar("_T")


def _all_subclasses(c: type[_T]) -> list[type[_T]]:
    return [c] + [subsubc for subc in c.__subclasses__() for subsubc in _all_subclasses(subc)]


saci_type_mapping: dict[str, type[SaciComponent]] = {
    f"{comp_type.__module__}.{comp_type.__qualname__}": comp_type for comp_type in _all_subclasses(SaciComponent)
}


class Base(DeclarativeBase):
    pass


# SQLAlchemy models matching the Pydantic models


class Component(Base):
    __tablename__ = "components"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]
    type_: Mapped[str]
    parameters: Mapped[dict[str, str]] = mapped_column(JSON)
    device_id = mapped_column(ForeignKey("devices.id"))
    is_entry: Mapped[bool]

    device: Mapped["Device"] = relationship(back_populates="components")
    ports: Mapped[list["Port"]] = relationship(back_populates="component", cascade="all, delete-orphan")
    capabilities: Mapped[list["Capability"]] = relationship(cascade="all, delete-orphan")

    @classmethod
    def from_web_model(cls, model: ComponentModel, device_id: str) -> Component:
        return cls(
            name=model.name,
            parameters=model.parameters,
            device_id=device_id,
        )

    def to_web_model(self) -> ComponentModel:
        return ComponentModel(name=str(self.name), parameters=self.parameters)

    def to_saci_component(self) -> SaciComponent:
        cls = saci_type_mapping.get(self.type_, SaciComponent)
        ports_dict = {
            port.name: SaciPort(direction=SaciPortDirection(port.direction) if port.direction else None)
            for port in self.ports
        }
        capabilities = {cap.to_tuple() for cap in self.capabilities}
        return cls(name=self.name, parameters=self.parameters, ports=ports_dict, capabilities=capabilities)


class Port(Base):
    __tablename__ = "ports"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]
    direction: Mapped[str | None]
    component_id: Mapped[int] = mapped_column(ForeignKey("components.id"))

    component: Mapped["Component"] = relationship(back_populates="ports")


class Connection(Base):
    __tablename__ = "port_connections"

    id: Mapped[int] = mapped_column(primary_key=True)
    from_port_id: Mapped[int] = mapped_column(ForeignKey("ports.id"))
    to_port_id: Mapped[int] = mapped_column(ForeignKey("ports.id"))
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"))

    from_port: Mapped[Port] = relationship(foreign_keys=[from_port_id])
    to_port: Mapped[Port] = relationship(foreign_keys=[to_port_id])
    device: Mapped["Device"] = relationship(back_populates="connections")

    # we should have from_port.component.device == to_port.component.device == device
    # (in this case we might not need device ourselves here? but keeping it for now)

    @classmethod
    def from_port_tuple(cls, port_tuple: tuple[int, int], device_id: str) -> Connection:
        return cls(
            from_port_id=port_tuple[0],
            to_port_id=port_tuple[1],
            device_id=device_id,
        )

    def to_port_tuple(self) -> tuple[int, int]:
        return (
            self.from_port_id,
            self.to_port_id,
        )

    def to_component_tuple(self) -> tuple[int, int]:
        """Legacy method for compatibility - returns component IDs instead of port IDs"""
        return (
            self.from_port.component_id,
            self.to_port.component_id,
        )


class Capability(Base):
    __tablename__ = "capabilities"

    id: Mapped[int] = mapped_column(primary_key=True)
    component_id: Mapped[int] = mapped_column(ForeignKey("components.id"))
    port_id: Mapped[int | None] = mapped_column(ForeignKey("ports.id"), nullable=True)
    capability: Mapped[str]

    component: Mapped["Component"] = relationship(overlaps="capabilities")
    port: Mapped["Port"] = relationship()

    def to_tuple(self) -> tuple[Capability, str | None]:
        return (CapabilityEnum(self.capability), self.port.name if self.port else None)


class Hypothesis(Base):
    __tablename__ = "hypotheses"

    id: Mapped[int] = mapped_column(primary_key=True)  # HypothesisID
    name: Mapped[str]
    path: Mapped[list[int]] = mapped_column(JSON)
    device_id = mapped_column(ForeignKey("devices.id"))
    extra_text: Mapped[str | None] = mapped_column(String, nullable=True)

    device: Mapped["Device"] = relationship(back_populates="hypotheses")
    annotations: Mapped[list["Annotation"]] = relationship(back_populates="hypothesis")

    @classmethod
    def from_web_model(
        cls,
        model: HypothesisModel,
        device_id: str,
        device_annotations: dict[AnnotationID, Annotation],
    ) -> Hypothesis:
        annotations = [device_annotations[annot_id] for annot_id in model.annotations]
        return cls(
            name=model.name,
            path=model.path,
            device_id=device_id,
            annotations=annotations,
            extra_text=model.extra_text,
        )

    def to_web_model(self) -> HypothesisModel:
        return HypothesisModel(
            name=self.name,
            path=[comp_id for comp_id in self.path],
            annotations=[annot.id for annot in self.annotations],
            extra_text=self.extra_text,
        )

    def to_saci_hypothesis(self) -> SaciHypothesis[int]:
        """Convert to a saci.hypothesis.Hypothesis for reasoning.

        Depends on Hypothesis.annotations being loaded or loadable.
        """
        return SaciHypothesis(
            description=self.name,
            path=self.path,
            annotations=[annot.to_saci_annotation() for annot in self.annotations],
        )


class Annotation(Base):
    __tablename__ = "annotations"

    id: Mapped[int] = mapped_column(primary_key=True)  # AnnotationID
    attack_surface_id: Mapped[int] = mapped_column(ForeignKey("components.id"))
    effect: Mapped[str]
    attack_model: Mapped[str | None]
    device_id = mapped_column(ForeignKey("devices.id"))
    hypothesis_id = mapped_column(ForeignKey("hypotheses.id"))

    attack_surface: Mapped[Component] = relationship()
    device: Mapped["Device"] = relationship(back_populates="annotations")
    hypothesis: Mapped[Hypothesis] = relationship(back_populates="annotations")

    @classmethod
    def from_web_model(cls, model: AnnotationModel, device_id: str) -> Annotation:
        return cls(
            attack_surface_id=model.attack_surface,
            effect=model.effect,
            attack_model=model.attack_model,
            device_id=device_id,
        )

    def to_web_model(self) -> AnnotationModel:
        return AnnotationModel(
            attack_surface=self.attack_surface_id,
            effect=self.effect,
            attack_model=self.attack_model,
        )

    def validate(self):
        if self.attack_surface.device_id != self.device_id:
            raise ValueError("Annotation's attack_surface should be a component of the annotation's device")

    def to_saci_annotation(self) -> SaciAnnotation[int]:
        match self.effect:
            case "entry":
                effect = MakeEntryEffect("annotation", frozenset([self.attack_surface_id]))
            case _:
                effect = VulnerabilityEffect("annotation")
        return SaciAnnotation(
            attack_surface=self.attack_surface_id,
            effect=effect,
            attack_model=self.attack_model,
            underlying_vulnerability=None,
        )


class Device(Base):
    __tablename__ = "devices"

    # TODO: don't have this be the primary key.
    id: Mapped[BlueprintID] = mapped_column(String, primary_key=True)
    name: Mapped[str]

    components = relationship("Component", back_populates="device", cascade="all, delete-orphan")
    connections = relationship("Connection", back_populates="device", cascade="all, delete-orphan")
    hypotheses = relationship("Hypothesis", back_populates="device", cascade="all, delete-orphan")
    annotations = relationship("Annotation", back_populates="device", cascade="all, delete-orphan")

    def to_web_model(self) -> DeviceModel:
        # Convert components
        components_dict = {comp.id: comp.to_web_model() for comp in self.components}

        # Convert connections - use component_tuple for backward compatibility with web models
        connections_list = [conn.to_component_tuple() for conn in self.connections]

        # Convert hypotheses
        hypotheses_dict = {hyp.id: hyp.to_web_model() for hyp in self.hypotheses}

        # Convert annotations
        annotations_dict = {annot.id: annot.to_web_model() for annot in self.annotations}

        return DeviceModel(
            name=str(self.name),
            components=components_dict,
            connections=connections_list,
            hypotheses=hypotheses_dict,
            annotations=annotations_dict,
        )

    def to_saci_device(self) -> SaciDevice:
        """Convert to a saci.modeling.Device.

        Uses Device.name, Device.components, and Device.connections.
        """
        graph = nx.DiGraph()
        for comp in self.components:
            graph.add_node(comp.id, is_entry=bool(comp.is_entry))
        for conn in self.connections:
            # Use component IDs from the connected ports for the graph edges
            graph.add_edge(conn.from_port.component_id, conn.to_port.component_id)
        return SaciDevice(
            name=self.name,
            components={comp.id: comp.to_saci_component() for comp in self.components},
            component_graph=graph,
        )

    @staticmethod
    def janky_from_saci_device(device_id: str, device: SaciDevice) -> "Device":
        """Please don't use this."""

        components = {
            comp_id: Component(
                name=comp.name,
                type_=f"{type(comp).__module__}.{type(comp).__qualname__}",
                parameters={pname: str(pvalue) for pname, pvalue in comp.parameters.items()},
            )
            for comp_id, comp in device.components.items()
        }

        # Create ports for each component
        for comp_id, comp in device.components.items():
            db_component = components[comp_id]
            db_component.ports = [
                Port(
                    name=port_name,
                    direction=str(port.direction) if port.direction else None,
                )
                for port_name, port in comp.ports.items()
            ]

        for comp_id, is_entry in device.component_graph.nodes(data="is_entry", default=False):  # type: ignore
            components[comp_id].is_entry = is_entry  # type: ignore

        # Create capabilities for each component
        for comp_id, comp in device.components.items():
            db_component = components[comp_id]
            db_component.capabilities = []
            for capability, port_name in comp.capabilities:
                if port_name:
                    # Find the port by name
                    port = next((p for p in db_component.ports if p.name == port_name), None)
                    db_component.capabilities.append(
                        Capability(
                            component=db_component,
                            port=port,
                            capability=str(capability),
                        )
                    )
                else:
                    db_component.capabilities.append(
                        Capability(
                            component=db_component,
                            port=None,
                            capability=str(capability),
                        )
                    )

        # Create port-based connections
        connections = []
        for from_id, to_id in device.component_graph.edges:
            from_component = components[from_id]
            to_component = components[to_id]

            # Find the first available port on each component
            if from_component.ports and to_component.ports:
                from_port = from_component.ports[0]  # Use first port
                to_port = to_component.ports[0]  # Use first port

                connections.append(
                    Connection(
                        from_port=from_port,
                        to_port=to_port,
                    )
                )

        return Device(
            id=device_id,
            name=device.name,
            components=list(components.values()),
            connections=connections,
            hypotheses=[],
            annotations=[],
        )


# Database connection functions
def get_engine(db_url: str | None = None) -> Engine:
    return create_engine(db_url or os.getenv("SACI_DATABASE_URL", "sqlite:///saci.db"))


def get_session(engine: Engine | None = None) -> Session:
    if engine is None:
        engine = get_engine()
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return SessionLocal()


def init_db(engine: Engine | None = None):
    if engine is None:
        engine = get_engine()
    Base.metadata.create_all(bind=engine)

    # Add the devices from saci-database to the database to start
    from saci_db.devices import devices

    with get_session(engine) as session, session.begin():
        for device_id, device in devices.items():
            if session.execute(select(Device).where(Device.id == device_id)).scalar() is None:
                db_device = Device.janky_from_saci_device(device_id, device)
                session.add(db_device)
