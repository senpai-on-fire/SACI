from __future__ import annotations
from dataclasses import dataclass
from collections import defaultdict
from enum import StrEnum

import json
import time
import importlib
from io import StringIO
from pathlib import Path
import os
from typing import Annotated

import httpx

# from flask import Flask, render_template, send_file, request, abort
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from saci.modeling.device.compass import CompassSensor

from saci.modeling.device.controller import Controller

from ..deserializer import ingest
from .scheduling import add_search, start_work_thread, SEARCHES
from ..modeling import Device, ComponentBase
from ..modeling.device import Wifi, Motor

app = FastAPI()
app.mount("/static", StaticFiles(directory="saci/webui/static"), name="static")
app.mount("/assets", StaticFiles(directory="web/dist/assets"), name="assets")
templates = Jinja2Templates(directory="saci/webui/templates")

start_work_thread()

APP_CONTROLLER_URL = "http://localhost:3000"


def get_component_abstractions(comp) -> dict[str, str]:
    if hasattr(comp, "ABSTRACTIONS"):
        d = {"99": "-"} | dict((str(level), abs_obj.__class__.__name__) for level, abs_obj in comp.ABSTRACTIONS.items())
        return d
    return {}


# my dumb JSON serializer
def json_serialize(obj) -> int | str | bool | list | dict:
    if isinstance(obj, dict):
        return dict((k, json_serialize(v)) for k, v in obj.items())
    elif isinstance(obj, (tuple, list)):
        return [json_serialize(item) for item in obj]
    elif isinstance(obj, (int, str, bool)):
        return obj
    elif obj is None:
        return "None"
    else:
        # object
        if hasattr(obj, "to_json_dict") and callable(obj.to_json_dict):
            return json_serialize(obj.to_json_dict())
        elif hasattr(obj, "__slot__"):
            d = {}
            for attr in obj.__slot__:
                d[attr] = json_serialize(getattr(obj, attr))
            return d
        else:
            return repr(obj)


@app.get("/")
async def serve_frontend_root():
    return FileResponse("web/dist/index.html")

class ComponentModel(BaseModel):
    name: str
    parameters: dict[str, object]

def component_to_model(comp: ComponentBase) -> ComponentModel:
    return ComponentModel(
        name=comp.name,
        parameters=dict(comp.parameters), # shallow copy to be safe -- oh, how i yearn for immutability by default
    )

ComponentID = str

def comp_id(comp: ComponentBase) -> ComponentID:
    # the graph is based on object identity, so i don't really see a better option here
    return str(id(comp))

class HypothesisModel(BaseModel):
    name: str
    entry_component: ComponentID
    exit_component: ComponentID

HypothesisID = str

class DeviceModel(BaseModel):
    name: str
    components: dict[ComponentID, ComponentModel]
    connections: list[tuple[ComponentID, ComponentID]]
    hypotheses: dict[HypothesisID, HypothesisModel]

def blueprint_to_model(bp: Device, hypotheses: dict[HypothesisID, HypothesisModel]) -> DeviceModel:
    return DeviceModel(
        name=bp.name,
        components={comp_id(comp): component_to_model(comp) for comp in bp.components},
        connections=[(comp_id(from_), comp_id(to_)) for (from_, to_) in bp.component_graph.edges],
        hypotheses=hypotheses,
    )

BlueprintID = str

@app.get('/api/blueprints')
def get_blueprints() -> dict[BlueprintID, DeviceModel]:
    # TODO: eventually we won't want to send all this data at once
    # TODO: store the hypotheses per-blueprint
    return {bp_id: blueprint_to_model(bp, hypotheses[bp_id]) for bp_id, bp in blueprints.items()}

class AnalysisUserInfo(BaseModel):
    """User-level metadata associated with an analysis type the user can run."""
    name: str
    components_included: list[ComponentID] = Field(default_factory=list)

class InteractionModel(StrEnum):
    UNKNOWN = "Unknown"
    X11 = "X11"

@dataclass(frozen=True)
class Analysis:
    """All the information associated with an analysis type, including what the system needs to know to launch it."""
    user_info: AnalysisUserInfo
    interaction_model: InteractionModel
    image: str

    def as_appconfig(self):
        return {
            "interaction_model": self.interaction_model,
            "image": self.image,
        }

@app.get("/api/blueprints/{bp_id}/analyses")
def get_analyses(bp_id: str) -> dict[str, AnalysisUserInfo]:
    # for now ignore bp_id, but eventually analyses will be available per-device or something.
    # return mapping of analysis ID to analysis info
    return {id_: analysis.user_info for id_, analysis in analyses.items()}

@app.post("/api/blueprints/{bp_id}/analyses/{analysis_id}/launch")
async def launch_analysis(bp_id: str, analysis_id: str):
    if analysis_id == "example":
        return "https://www.example.com"
    if analysis_id not in analyses:
        raise HTTPException(status_code=400, detail="analysis not found")
    analysis = analyses[analysis_id]
    async with httpx.AsyncClient() as client:
        create_resp = await client.post(f"{APP_CONTROLLER_URL}/app", data=analysis.as_appconfig())
        if not create_resp.is_success:
            print(f"got error {create_resp.text} when trying to create analysis")
            raise HTTPException(status_code=500, detail="couldn't create analysis")
        app = create_resp.json()
        start_resp = await client.post(f"{APP_CONTROLLER_URL}/app/{app['id']}/start")
        if not start_resp.is_success:
            raise HTTPException(status_code=500, detail="couldn't start analysis")
        return start_resp.json()["url"]

@app.get("/api/cpv_info")
def cpv_info(name: str):
    for cpv in CPVS:
        if cpv.__class__.__name__ == name:
            return {
                "name": cpv.NAME,
                "entry_component": cpv.entry_component.__class__.__name__ if cpv.entry_component else "N/A",
                "exit_component": cpv.exit_component.__class__.__name__ if cpv.exit_component else "N/A",
                "required_components": [comp.__class__.__name__ for comp in cpv.required_components],
                "initial_conditions": cpv.initial_conditions or {},  # Include initial_conditions
                "vulnerabilities": [vuln.__class__.__name__ for vuln in cpv.vulnerabilities],  # Extract vulnerabilities
                "reference_urls": cpv.reference_urls,  # Include reference_urls directly
                "attack_requirements": cpv.attack_requirements,
                "attack_vectors": [
                    {
                        "name": vector.name,
                        "signal": vector.signal.modality,
                        "access_level": vector.required_access_level,
                        "configuration": vector.configuration,  # Pass configuration as a dictionary
                    }
                    for vector in cpv.attack_vectors
                ],
                "impact": [
                    {"category": impact.category, "description": impact.description}
                    for impact in cpv.attack_impacts
                ],
                "exploit_steps": cpv.exploit_steps,
            }
    return {"error": "CPV not found"}, 400


def lookup_blueprint(raw):
    try:
        blueprint_id = int(raw)
        if blueprint_id >= len(blueprints):
            return None
        return blueprints[blueprint_id]
    except (TypeError, ValueError):
        return None

@app.post("/api/ingest_blueprint")
def ingest_blueprint(name: str, serialized: dict, force: bool = False):
    if name in blueprints:
        return {"error": "exists"}, 400
    try:
        # TODO: move this to another thread and return a promise?
        ingest(serialized, INGESTION_DIR / name, force=force)
    except FileExistsError as e:
        return {"error": "exists"}, 400
    except ValueError as e:
        print(e)
        return {"error": "couldn't deserialize blueprint"}, 400

    importlib.invalidate_caches()
    # TODO: probably don't need to reload *all* the ingested modules
    importlib.reload(ingested)
    # TODO: should probably just separate builtin and ingested blueprints...
    blueprint_id = "ingested/" + name
    device = ingested.devices[blueprint_id]
    blueprints[blueprint_id] = device

    return {"id": blueprint_id, "name": device.name}

@app.get("/api/get_blueprint")
def get_blueprint(blueprint_id: Annotated[str, Query(alias="id")]):
    if blueprint_id not in blueprints:
        return {"error": "Blueprint not found"}
    
    cps = blueprints[blueprint_id]
    
    d = {
        "nodes": [],
        "links": [],
        "options": {},
    }
    
    for node in cps.component_graph:
        d["nodes"].append({
        "id": id(node), 
        "name": repr(node),
        "entry": cps.component_graph.nodes[node].get('is_entry', False)
        })
    for src, dst in cps.component_graph.edges:
        d["links"].append({
            "source": id(src),
            "target": id(dst),
        })
    
    for option in cps.options:
        d["options"][option] = cps.get_option(option)
    
    return {
        "component_graph": d
    }


@app.post("/api/set_blueprint_option")
def set_blueprint_option(
    blueprint_id: Annotated[str, Query(alias="id")],
    option: str,
    value: dict,
):
    if blueprint_id not in blueprints:
        return {"error": "Blueprint not found"}
    cps = blueprints[blueprint_id]

    cps.set_option(option, value)
    #print(cps.steering.has_aps)

    return {}

@app.get("/api/cpv_search")
def cpv_search(blueprint_id: str):
    if blueprint_id not in blueprints:
        return {"error": "Blueprint not found"}

    cps = blueprints[blueprint_id]
    search_id = add_search(cps=cps)

    # Wait briefly for the worker to start
    time.sleep(1)

    search = SEARCHES.get(search_id, {})
    if not search.get("cpv_inputs"):
        return {"error": "No CPVs found for this CPS."}

    # Return only ID and name of each CPV
    return {"cpvs": search["cpv_inputs"]}

@app.get("/api/cpv_search_ids")
def cpv_search_ids():

    ids = list(SEARCHES)

    return {
        "ids": ids,
    }

@app.get("/api/cpv_search_result")
def cpv_search_result(search_id: Annotated[str, Query(alias="id")]):
    if search_id is None:
        return {
            "error": "Search ID cannot be None",
        }

    try:
        search = SEARCHES.get(int(search_id), None)
    except TypeError:
        search = None

    if search is None:
        return {
            "error": "Search not found"
        }

    result = {
        "taken": search.get("taken", False),
        "result": search.get("result", None),
        # "identified_cpv_and_paths": search.get("identified_cpv_and_paths", None),
        "cpv_inputs": search.get("cpv_inputs", None),
        "last_updated": search.get("last_updated", int(time.time() * 10000)),
        "tasks": search.get("tasks", None),
    }

    return json_serialize(result)

# delayed import
from saci_db.devices import devices, ingested
from saci_db.cpvs import CPVS

if (dirname := os.getenv("INGESTION_DIR")) is not None:
    INGESTION_DIR = Path(dirname)
else:
    INGESTION_DIR = Path(ingested.__file__).resolve().parent
del dirname

blueprints: dict[BlueprintID, Device] = devices | ingested.devices

# TODO: this is hacky and an indication that we should have a better way of doing this...
def _find_comps(device: Device, comp_type: type[ComponentBase]) -> list[ComponentBase]:
    return [comp for comp in device.components if isinstance(comp, comp_type)]

def _find_comp(device: Device, comp_type: type[ComponentBase]) -> ComponentBase:
    comps = _find_comps(device, comp_type)
    if len(comps) == 0:
        raise ValueError(f"device {device!r} has no component of type {comp_type}")
    elif len(comps) > 1:
        raise ValueError(f"device {device!r} has more than one component of type {comp_type}")
    else:
        return comps[0]

rover = blueprints["ngcrover"]
hypotheses: dict[BlueprintID, dict[HypothesisID, HypothesisModel]] = defaultdict(dict, {
    "ngcrover": {
        "webserver_stop": HypothesisModel(
            name="From the webserver, stop the rover.",
            entry_component=comp_id(_find_comp(rover, Wifi)),
            exit_component=comp_id(_find_comp(rover, Motor)),
        ),
    },
})

analyses = {
    "example": Analysis(
        user_info=AnalysisUserInfo(name="Example"),
        interaction_model=InteractionModel.UNKNOWN,
        image="???",
    ),
    "taveren_model": Analysis(
        user_info=AnalysisUserInfo(
            name="Ta'veren Model",
            # TODO: hackyyyyy... should either give the different controllers different names or have some nice query mechanism
            components_included=[comp_id(_find_comps(rover, Controller)[0])],
        ),
        interaction_model=InteractionModel.X11,
        image="???",
    ),
    "taveren_sim": Analysis(
        user_info=AnalysisUserInfo(
            name="Ta'veren Simulation",
            components_included=[comp_id(_find_comps(rover, Controller)[0])],
        ),
        interaction_model=InteractionModel.X11,
        image="ghcr.io/twizmwazin/app-controller/firefox-demo:latest",
    ),
    "gazebo_compass": Analysis(
        user_info=AnalysisUserInfo(
            name="Gazebo Compass Model",
            components_included=[
                comp_id(_find_comps(rover, Controller)[0]),
                comp_id(_find_comp(rover, CompassSensor)),
            ],
        ),
        interaction_model=InteractionModel.X11,
        image="???",
    ),
}
