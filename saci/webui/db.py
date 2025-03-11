from __future__ import annotations
import os

from sqlalchemy import (
    Column,
    Engine,
    String,
    Integer,
    ForeignKey,
    Table,
    create_engine,
    JSON,
)
from sqlalchemy.orm import (
    relationship,
    sessionmaker,
    DeclarativeBase,
    Session,
    mapped_column,
    Mapped,
)
import uuid

# Import web models for conversion methods
from saci.webui.web_models import (
    BlueprintID,
    ComponentModel,
    HypothesisModel,
    AnnotationModel,
    DeviceModel,
    ComponentID,
)

class Base(DeclarativeBase):
    type_annotation_map = {
        ComponentID: String,
    }


# Connection table for many-to-many relationships
device_component_association = Table(
    "device_component_association",
    Base.metadata,
    Column("device_id", String, ForeignKey("devices.id")),
    Column("component_id", String, ForeignKey("components.id")),
)

connection_table = Table(
    "connections",
    Base.metadata,
    Column("id", Integer, primary_key=True),
    Column("device_id", String, ForeignKey("devices.id")),
    Column("from_component", String),
    Column("to_component", String),
)

# SQLAlchemy models matching the Pydantic models


class Component(Base):
    __tablename__ = "components"

    id: Mapped[ComponentID] = mapped_column(String, primary_key=True)
    name: Mapped[str]
    parameters: Mapped[dict[str, str]] = mapped_column(JSON)
    device_id = mapped_column(String, ForeignKey("devices.id"))

    device = relationship("Device", back_populates="components")

    @classmethod
    def from_web_model(
        cls, model: ComponentModel, component_id: str, device_id: str
    ) -> Component:
        return cls(
            id=component_id,
            name=model.name,
            parameters=model.parameters,
            device_id=device_id,
        )

    def to_web_model(self) -> ComponentModel:
        return ComponentModel(name=str(self.name), parameters=self.parameters)


class Connection(Base):
    __tablename__ = "component_connections"

    id = mapped_column(Integer, primary_key=True)
    from_component: Mapped[ComponentID]
    to_component: Mapped[ComponentID]
    device_id = mapped_column(String, ForeignKey("devices.id"))

    device = relationship("Device", back_populates="connections")

    @classmethod
    def from_connection_tuple(
        cls, conn_tuple: tuple[str, str], device_id: str
    ) -> Connection:
        return cls(
            from_component=conn_tuple[0],
            to_component=conn_tuple[1],
            device_id=device_id,
        )

    def to_connection_tuple(self) -> tuple[ComponentID, ComponentID]:
        return (
            self.from_component,
            self.to_component,
        )


class Hypothesis(Base):
    __tablename__ = "hypotheses"

    id = mapped_column(String, primary_key=True)  # HypothesisID
    name: Mapped[str]
    entry_component: Mapped[ComponentID | None]
    exit_component: Mapped[ComponentID | None]
    device_id = mapped_column(String, ForeignKey("devices.id"))

    device = relationship("Device", back_populates="hypotheses")

    @classmethod
    def from_web_model(
        cls, model: HypothesisModel, hypothesis_id: str, device_id: str
    ) -> Hypothesis:
        return cls(
            id=hypothesis_id,
            name=model.name,
            entry_component=model.entry_component,
            exit_component=model.exit_component,
            device_id=device_id,
        )

    def to_web_model(self) -> HypothesisModel:
        entry_comp = self.entry_component
        exit_comp = self.exit_component

        return HypothesisModel(
            name=str(self.name),
            entry_component=entry_comp if entry_comp is not None else None,
            exit_component=exit_comp if exit_comp is not None else None,
        )


class Annotation(Base):
    __tablename__ = "annotations"

    id = mapped_column(String, primary_key=True)  # AnnotationID
    attack_surface: Mapped[ComponentID]
    effect: Mapped[str]
    attack_model: Mapped[str | None]
    device_id = mapped_column(String, ForeignKey("devices.id"))

    device = relationship("Device", back_populates="annotations")

    @classmethod
    def from_web_model(
        cls, model: AnnotationModel, annotation_id: str, device_id: str
    ) -> Annotation:
        return cls(
            id=annotation_id,
            attack_surface=model.attack_surface,
            effect=model.effect,
            attack_model=model.attack_model,
            device_id=device_id,
        )

    def to_web_model(self) -> AnnotationModel:
        attack_model_val = self.attack_model

        return AnnotationModel(
            attack_surface=self.attack_surface,
            effect=str(self.effect),
            attack_model=str(attack_model_val)
            if attack_model_val is not None
            else None,
        )


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[BlueprintID] = mapped_column(String, primary_key=True)
    name: Mapped[str]

    components = relationship(
        "Component", back_populates="device", cascade="all, delete-orphan"
    )
    connections = relationship(
        "Connection", back_populates="device", cascade="all, delete-orphan"
    )
    hypotheses = relationship(
        "Hypothesis", back_populates="device", cascade="all, delete-orphan"
    )
    annotations = relationship(
        "Annotation", back_populates="device", cascade="all, delete-orphan"
    )

    @classmethod
    def from_web_model(cls, model: DeviceModel, device_id: str | None = None) -> Device:
        if device_id is None:
            device_id = str(uuid.uuid4())

        device = cls(id=device_id, name=model.name)

        # Add components
        for comp_id, comp_model in model.components.items():
            device.components.append(
                Component.from_web_model(comp_model, comp_id, device_id)
            )

        # Add connections
        for conn_tuple in model.connections:
            device.connections.append(
                Connection.from_connection_tuple(conn_tuple, device_id)
            )

        # Add hypotheses
        for hyp_id, hyp_model in model.hypotheses.items():
            device.hypotheses.append(
                Hypothesis.from_web_model(hyp_model, hyp_id, device_id)
            )

        # Add annotations
        for annot_id, annot_model in model.annotations.items():
            device.annotations.append(
                Annotation.from_web_model(annot_model, annot_id, device_id)
            )

        return device

    def to_web_model(self) -> DeviceModel:
        # Convert components
        components_dict = {comp.id: comp.to_web_model() for comp in self.components}

        # Convert connections
        connections_list = [conn.to_connection_tuple() for conn in self.connections]

        # Convert hypotheses
        hypotheses_dict = {hyp.id: hyp.to_web_model() for hyp in self.hypotheses}

        # Convert annotations
        annotations_dict = {
            annot.id: annot.to_web_model() for annot in self.annotations
        }

        return DeviceModel(
            name=str(self.name),
            components=components_dict,
            connections=connections_list,
            hypotheses=hypotheses_dict,
            annotations=annotations_dict,
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
