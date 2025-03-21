import logging
import os
from collections import defaultdict
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Literal, TypeVar

from pydantic import BaseModel

from saci_db.devices import devices, ingested

from saci.modeling.annotation import Annotation
from saci.modeling.device import ComponentBase, ComponentID
from saci.modeling.device.device import Device
from saci.webui.web_models import (
    AnalysisID,
    AnalysisUserInfo,
    AnnotationID,
    BlueprintID,
    ComponentTypeID,
    HypothesisID,
    HypothesisModel,
)

log = logging.getLogger(__name__)

T = TypeVar("T")


def _all_subclasses(c: type[T]) -> list[type[T]]:
    return [c] + [subsubc for subc in c.__subclasses__() for subsubc in _all_subclasses(subc)]


def component_type_id(comp_type: type[ComponentBase]) -> str:
    return f"{comp_type.__module__}.{comp_type.__qualname__}"


# TODO: so janky
all_component_types: dict[ComponentTypeID, type[ComponentBase]] = {}
for comp_type in _all_subclasses(ComponentBase):
    type_id = component_type_id(comp_type)
    if dup := all_component_types.get(type_id):
        log.warning(
            f"duplicately-IDed component types {dup} and {comp_type} (both have ID {type_id}), only including {dup}"
        )
    all_component_types[type_id] = comp_type


class InteractionModel(StrEnum):
    UNKNOWN = "Unknown"
    X11 = "X11"


class ContainerConfig(BaseModel):
    image: str
    config: str
    image_pull_policy: Literal["Always", "IfNotPresent", "Never"]


class AppConfig(BaseModel):
    name: str
    interaction_model: InteractionModel
    containers: list[ContainerConfig]
    always_pull_images: bool
    enable_docker: bool
    autostart: bool


@dataclass(frozen=True)
class Analysis:
    """All the information associated with an analysis type, including what the system needs to know to launch it."""

    user_info: AnalysisUserInfo
    interaction_model: InteractionModel
    images: list[str]

    def as_appconfig(self):
        return {
            "name": "app",
            "interaction_model": self.interaction_model,
            "images": self.images,
            "always_pull_images": False,
        }


if (dirname := os.getenv("INGESTION_DIR")) is not None:
    INGESTION_DIR = Path(dirname)
else:
    INGESTION_DIR = Path(ingested.__file__).resolve().parent
del dirname

blueprints: dict[BlueprintID, Device] = devices | ingested.devices


# TODO: this is hacky and an indication that we should have a better way of doing this...
def _find_comps(device: Device, comp_type: type[ComponentBase]) -> list[ComponentID]:
    return [comp_id for comp_id, comp in device.components.items() if isinstance(comp, comp_type)]


def _find_comp(device: Device, comp_type: type[ComponentBase]) -> ComponentID:
    comps = _find_comps(device, comp_type)
    if len(comps) == 0:
        raise ValueError(f"device {device!r} has no component of type {comp_type}")
    elif len(comps) > 1:
        raise ValueError(f"device {device!r} has more than one component of type {comp_type}")
    else:
        return comps[0]


rover = blueprints["ngcrover"]

analyses: dict[AnalysisID, Analysis] = {
    "foo": Analysis(
        user_info=AnalysisUserInfo(
            name="SWAB",
            components_included=[
                4,
                5,
                # "compass",
                # "uno_r4",
            ],
        ),
        interaction_model=InteractionModel.X11,
        images=[],
    ),
}
hypotheses: dict[BlueprintID, dict[HypothesisID, HypothesisModel]] = defaultdict(dict)
annotations: dict[BlueprintID, dict[AnnotationID, Annotation]] = defaultdict(dict)

# analyses: dict[AnalysisID, Analysis] = {
#     "taveren_model": Analysis(
#         user_info=AnalysisUserInfo(
#             name="Model: Ta'veren Controller",
#             # TODO: hackyyyyy... should either use different controllers' different IDs (now that they have them!)
#             # or have some nice query mechanism
#             components_included=[
#                 _find_comps(rover, WebServer)[0],
#                 _find_comps(rover, Controller)[0],
#             ],
#         ),
#         interaction_model=InteractionModel.X11,
#         images=["taveren:latest"],
#     ),
#     "binsync_re": Analysis(
#         user_info=AnalysisUserInfo(
#             name="Model: BinSync-enabled RE",
#             components_included=[_find_comps(rover, Controller)[0]],
#         ),
#         interaction_model=InteractionModel.X11,
#         images=["ghcr.io/twizmwazin/app-controller/firefox-demo:latest"],
#     ),
#     "hybrid_automata": Analysis(
#         user_info=AnalysisUserInfo(
#             name="Model: Hybrid Automata",
#             components_included=_find_comps(rover, Controller)
#             + [
#                 _find_comp(rover, GPSReceiver),
#                 _find_comp(rover, CompassSensor),
#                 _find_comp(rover, Steering),
#                 _find_comp(rover, ESC),
#                 _find_comp(rover, Motor),
#             ],
#         ),
#         interaction_model=InteractionModel.X11,
#         images=["ghcr.io/twizmwazin/app-controller/firefox-demo:latest"],
#     ),
#     "gazebo_hybrid_automata": Analysis(
#         user_info=AnalysisUserInfo(
#             name="Co-Simulation: Gazebo + Hybrid Automata",
#             components_included=_find_comps(rover, Controller)
#             + [
#                 _find_comp(rover, GPSReceiver),
#                 _find_comp(rover, CompassSensor),
#                 _find_comp(rover, Steering),
#                 _find_comp(rover, ESC),
#                 _find_comp(rover, Motor),
#             ],
#         ),
#         interaction_model=InteractionModel.X11,
#         images=[
#             "ghcr.io/cpslab-asu/gzcm/px4/firmware:0.2.0",
#             "ghcr.io/cpslab-asu/gzcm/px4/gazebo:harmonic",
#         ],
#     ),
#     "gazebo_firmware": Analysis(
#         user_info=AnalysisUserInfo(
#             name="Co-Simulation: Gazebo + Firmware",
#             components_included=_find_comps(rover, Controller)
#             + [
#                 _find_comp(rover, GPSReceiver),
#                 _find_comp(rover, CompassSensor),
#                 _find_comp(rover, Steering),
#                 _find_comp(rover, ESC),
#                 _find_comp(rover, Motor),
#             ],
#         ),
#         interaction_model=InteractionModel.X11,
#         images=["onex:latest"],
#     ),
# }

# hypotheses: dict[BlueprintID, dict[HypothesisID, HypothesisModel]] = defaultdict(
#     dict,
#     {
#         "ngcrover": {
#             "webserver_stop": HypothesisModel(
#                 name="From the webserver, stop the rover.",
#                 path=[
#                     ComponentID("wifi"),
#                     ComponentID("webserver"),
#                     ComponentID("uno_r4"),
#                     ComponentID("uno_r3"),
#                     ComponentID("pwm_channel_esc"),
#                     ComponentID("esc"),
#                     ComponentID("motor"),
#                 ],
#                 annotations=["wifi_open", "hidden_stop"],
#             ),
#             "emi_compass": HypothesisModel(
#                 name="Using EMI, influence the compass to affect the mission.",
#                 path=[
#                     ComponentID("compass"),
#                     ComponentID("uno_r4"),
#                     ComponentID("uno_r3"),
#                     ComponentID("pwm_channel_servo"),
#                     ComponentID("steering"),
#                 ],
#                 annotations=[],
#             ),
#             "wifi_rollover": HypothesisModel(
#                 name="Over WiFi, subvert the control system to roll the rover.",
#                 path=[
#                     ComponentID("wifi"),
#                     ComponentID("webserver"),
#                     ComponentID("uno_r4"),
#                     ComponentID("uno_r3"),
#                     ComponentID("pwm_channel_esc"),
#                     ComponentID("esc"),
#                     ComponentID("motor"),
#                 ],
#                 annotations=["wifi_open"],
#             ),
#         },
#     },
# )

# annotations: dict[BlueprintID, dict[AnnotationID, Annotation]] = defaultdict(
#     dict,
#     {
#         "ngcrover": {
#             "wifi_open": Annotation(
#                 attack_surface=ComponentID("wifi"),
#                 effect=MakeEntryEffect(
#                     reason="wifi is open", nodes=frozenset([ComponentID("wifi")])
#                 ),
#                 underlying_vulnerability=None,
#                 attack_model="connect to the AP without creds",
#             ),
#             "hidden_stop": Annotation(
#                 attack_surface=ComponentID("webserver"),
#                 effect=VulnerabilityEffect(
#                     reason="hidden stop command in the webserver"
#                 ),
#                 underlying_vulnerability=None,
#                 attack_model="hit the stop endpoint on the webserver",
#             ),
#         },
#     },
# )
