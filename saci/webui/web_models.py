from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, Field

from saci.modeling.annotation import Annotation
from saci.modeling.cpv import CPV
from saci.modeling.cpvpath import CPVPath
from saci.modeling.device.component.component_base import ComponentBase
from saci.modeling.device.componentid import ComponentID
from saci.modeling.device.device import Device
from saci.modeling.vulnerability.base_vuln import VulnerabilityEffect


class ComponentModel(BaseModel):
    name: str
    parameters: dict[str, str]

    @staticmethod
    def from_component(comp: ComponentBase) -> ComponentModel:
        """Convert a ComponentBase instance to a ComponentModel."""
        return ComponentModel(
            name=comp.name,
            parameters={
                param_name: str(param_value)
                for param_name, param_value in comp.parameters.items()
            },
        )


class HypothesisModel(BaseModel):
    name: str
    entry_component: ComponentID | None
    exit_component: ComponentID | None


HypothesisID = str


class AnnotationModel(BaseModel):
    attack_surface: ComponentID
    effect: str  # TODO: add an EffectModel to capture the actual semantic data associated with a VulnerabilityEffect
    attack_model: str | None

    @staticmethod
    def from_annotation(annot: Annotation) -> AnnotationModel:
        return AnnotationModel(
            attack_surface=annot.attack_surface,
            effect=annot.effect.reason,
            attack_model=annot.attack_model,
        )

    def to_annotation(self) -> Annotation:
        return Annotation(
            attack_surface=self.attack_surface,
            effect=VulnerabilityEffect(reason=self.effect),
            attack_model=self.attack_model,
            underlying_vulnerability=None,
        )


AnnotationID = str


class DeviceModel(BaseModel):
    name: str
    components: dict[ComponentID, ComponentModel]
    connections: list[tuple[ComponentID, ComponentID]]
    hypotheses: dict[HypothesisID, HypothesisModel]
    annotations: dict[AnnotationID, AnnotationModel]

    @staticmethod
    def from_device(
        bp: Device,
        hypotheses: dict[HypothesisID, HypothesisModel],
        annotations: dict[AnnotationID, Annotation],
    ) -> DeviceModel:
        return DeviceModel(
            name=bp.name,
            components={
                comp_id: ComponentModel.from_component(comp)
                for comp_id, comp in bp.components.items()
            },
            connections=[(from_, to_) for (from_, to_) in bp.component_graph.edges],
            hypotheses=hypotheses,
            annotations={
                annot_id: AnnotationModel.from_annotation(annot)
                for annot_id, annot in annotations.items()
            },
        )


BlueprintID = str


class CPVModel(BaseModel):
    name: str
    exploit_steps: list[str]

    @staticmethod
    def from_cpv(cpv: CPV) -> CPVModel:
        exploit_steps = cpv.exploit_steps if hasattr(cpv, 'exploit_steps') else []

        return CPVModel(
            name=cpv.NAME,
            exploit_steps=exploit_steps
        )


class CPVPathModel(BaseModel):
    path: list[ComponentID]

    @staticmethod
    def from_cpv_path(path: CPVPath) -> CPVPathModel:
        return CPVPathModel(path=[c.id_ for c in path.path])


class CPVResultModel(BaseModel):
    cpv: CPVModel
    path: CPVPathModel

    @staticmethod
    def from_cpv_result(cpv: CPV, path: CPVPath) -> CPVResultModel:
        return CPVResultModel(cpv=CPVModel.from_cpv(cpv), path=CPVPathModel.from_cpv_path(path))


class ParameterTypeModel(BaseModel):
    type_: Annotated[str, Field(serialization_alias="type")]
    description: str


class PortModel(BaseModel):
    direction: str


class ComponentTypeModel(BaseModel):
    name: str  # human-readable name
    parameters: dict[str, ParameterTypeModel]
    ports: dict[str, PortModel]


ComponentTypeID = str


class AnalysisUserInfo(BaseModel):
    """User-level metadata associated with an analysis type the user can run."""

    name: str
    components_included: list[ComponentID] = Field(default_factory=list)


AnalysisID = str
