from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, Field, PlainSerializer

from saci.hypothesis import Hypothesis
from saci.modeling.annotation import Annotation
from saci.modeling.cpv import CPV
from saci.modeling.cpvpath import CPVPath
from saci.modeling.device.component.component_base import ComponentBase
from saci.modeling.device.device import Device
from saci.modeling.device import ComponentID
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

IntJSONStr = Annotated[int, PlainSerializer(str, return_type=str, when_used='json')]

# TODO: NOT to be confused with the ComponentID used in devices. CERTAINLY need to rename one at some point. Or better
# yet make Device generic over it.
WebComponentID = IntJSONStr

class AnnotationModel(BaseModel):
    attack_surface: WebComponentID
    effect: str  # TODO: add an EffectModel to capture the actual semantic data associated with a VulnerabilityEffect
    attack_model: str | None

    @staticmethod
    def from_annotationn(annot: Annotation[WebComponentID]) -> AnnotationModel:
        return AnnotationModel(
            attack_surface=annot.attack_surface,
            effect=annot.effect.reason,
            attack_model=annot.attack_model,
        )

    def to_annotation(self) -> Annotation[WebComponentID]:
        return Annotation(
            attack_surface=self.attack_surface,
            effect=VulnerabilityEffect(reason=self.effect),
            attack_model=self.attack_model,
            underlying_vulnerability=None,
        )


AnnotationID = IntJSONStr


class HypothesisModel(BaseModel):
    name: str
    path: list[WebComponentID]
    annotations: list[AnnotationID]

    def to_hypothesis(self, annotation_mapping: dict[AnnotationID, Annotation]) -> Hypothesis[WebComponentID]:
        return Hypothesis(
            description=self.name,
            path=self.path,
            assumptions=[], # hopefully my idea for assumptions will come to pass... i think at some point they will
                            # merge with annotations. but for now, empty
            annotations=[annotation_mapping[annot_id] for annot_id in self.annotations],
        )


HypothesisID = IntJSONStr


class DeviceModel(BaseModel):
    name: str
    components: dict[WebComponentID, ComponentModel]
    connections: list[tuple[WebComponentID, WebComponentID]]
    hypotheses: dict[HypothesisID, HypothesisModel]
    annotations: dict[AnnotationID, AnnotationModel]

    @staticmethod
    def from_device(
        bp: Device,
        hypotheses: dict[HypothesisID, HypothesisModel],
        annotations: dict[AnnotationID, Annotation[WebComponentID]],
    ) -> DeviceModel:
        return DeviceModel(
            name=bp.name,
            components={
                comp_id: ComponentModel.from_component(comp)
                for comp_id, comp in bp.components.items()
            },
            connections=list(bp.component_graph.edges),
            hypotheses=hypotheses,
            annotations={
                annot_id: AnnotationModel.from_annotationn(annot)
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
    path: list[WebComponentID]

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
    components_included: list[WebComponentID] = Field(default_factory=list)


AnalysisID = str
