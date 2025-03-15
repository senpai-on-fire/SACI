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
    AnnotationID,
)

class Base(DeclarativeBase):
    type_annotation_map = {
        ComponentID: String,
    }

# SQLAlchemy models matching the Pydantic models


class Component(Base):
    __tablename__ = "components"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]
    type_: Mapped[str]
    parameters: Mapped[dict[str, str]] = mapped_column(JSON)
    device_id = mapped_column(ForeignKey("devices.id"))

    device: Mapped["Device"] = relationship(back_populates="components")

    @classmethod
    def from_web_model(
        cls, model: ComponentModel, device_id: str
    ) -> Component:
        return cls(
            name=model.name,
            parameters=model.parameters,
            device_id=device_id,
        )

    def to_web_model(self) -> ComponentModel:
        return ComponentModel(name=str(self.name), parameters=self.parameters)


class Connection(Base):
    __tablename__ = "component_connections"

    id: Mapped[int] = mapped_column(primary_key=True)
    from_component_id = mapped_column(ForeignKey("components.id"))
    to_component_id = mapped_column(ForeignKey("components.id"))
    device_id = mapped_column(ForeignKey("devices.id"))

    from_component: Mapped[Component] = relationship(foreign_keys=from_component_id)
    to_component: Mapped[Component] = relationship(foreign_keys=to_component_id)
    device: Mapped["Device"] = relationship(back_populates="connections")

    # we should have from_component.device == to_component.device == device
    # (in this case we might not need device ourselves here? but keeping it for now)

    @classmethod
    def from_connection_tuple(
        cls, conn_tuple: tuple[int, int], device_id: str
    ) -> Connection:
        return cls(
            from_component_id=conn_tuple[0],
            to_component_id=conn_tuple[1],
            device_id=device_id,
        )

    def to_connection_tuple(self) -> tuple[int, int]:
        return (
            self.from_component_id,
            self.to_component_id,
        )


class Hypothesis(Base):
    __tablename__ = "hypotheses"

    id: Mapped[int] = mapped_column(primary_key=True)  # HypothesisID
    name: Mapped[str]
    path: Mapped[list[int]] = mapped_column(JSON)
    device_id = mapped_column(ForeignKey("devices.id"))

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
        )

    def to_web_model(self) -> HypothesisModel:
        return HypothesisModel(
            name=self.name,
            path=[comp_id for comp_id in self.path],
            annotations=[annot.id for annot in self.annotations],
        )


class Annotation(Base):
    __tablename__ = "annotations"

    id: Mapped[int] = mapped_column(primary_key=True)  # AnnotationID
    attack_surface_id: Mapped[int] = mapped_column(ForeignKey("components.id"))
    effect: Mapped[str]
    attack_model: Mapped[str | None]
    device_id = mapped_column(String, ForeignKey("devices.id"))
    hypothesis_id = mapped_column(String, ForeignKey("hypotheses.id"))

    attack_surface: Mapped[Component] = relationship()
    device: Mapped["Device"] = relationship(back_populates="annotations")
    hypothesis: Mapped[Hypothesis] = relationship(back_populates="annotations")

    @classmethod
    def from_web_model(
        cls, model: AnnotationModel, device_id: str
    ) -> Annotation:
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


class Device(Base):
    __tablename__ = "devices"

    # TODO: don't have this be the primary key.
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
