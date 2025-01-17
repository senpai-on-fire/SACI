from __future__ import annotations
from dataclasses import dataclass
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
from fastapi import FastAPI, Query, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from ..deserializer import ingest
from .scheduling import add_search, start_work_thread, SEARCHES
from ..modeling import CPVHypothesis

app = FastAPI()
app.mount("/static", StaticFiles(directory="saci/webui/static"), name="static")
templates = Jinja2Templates(directory="saci/webui/templates")

start_work_thread()

hypotheses = {}

APP_CONTROLLER_URL = "http://localhost:4321"


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


@app.route('/')
def index(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"cpvs": CPVS, "blueprints": blueprints},
    )

class AnalysisUserInfo(BaseModel):
    """User-level metadata associated with an analysis type the user can run."""
    name: str

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

ANALYSES = {
    "taveren_model": Analysis(
        user_info=AnalysisUserInfo(name="Ta'veren Model"),
        interaction_model=InteractionModel.X11,
        image="???",
    ),
    "taveren_sim": Analysis(
        user_info=AnalysisUserInfo(name="Ta'veren Simulation"),
        interaction_model=InteractionModel.X11,
        image="???",
    ),
}

@app.get("/api/blueprints/{bp_id}/analyses")
def get_analyses(bp_id: str) -> dict[str, AnalysisUserInfo]:
    # for now ignore bp_id, but eventually analyses will be available per-device or something.
    # return mapping of analysis ID to analysis info
    return {id_: analysis.user_info for id_, analysis in ANALYSES.items()}

@app.post("/api/blueprints/{bp_id}/analyses/{analysis_id}/launch")
async def launch_analysis(bp_id: str, analysis_id: str):
    if analysis_id not in ANALYSES:
        return {"error": "analysis not found"}, 400
    analysis = ANALYSES[analysis_id]
    async with httpx.AsyncClient() as client:
        create_resp = await client.post(f"{APP_CONTROLLER_URL}/app", data=analysis.as_appconfig())
        if not create_resp.is_success:
            return {"error": "couldn't create analysis"}, 500
        app = create_resp.json()
        start_resp = await client.post(f"{APP_CONTROLLER_URL}/app/{app['id']}/start")
        if not start_resp.is_success:
            return {"error": "couldn't start analysis"}, 500
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

@app.post("/api/add_hypothesis")
def add_hypothesis(name: str, required_components: list[str]):
    if name in hypotheses:
        return {"error": "hypothesis name already taken"}, 400
    # TODO: why are we stringifying here...
    hypotheses[name] = CPVHypothesis(StringIO(json.dumps({
        "Name": name,
        "Required Components": required_components,
        "Kinetic Effect": "do something, or not",
        "Vulnerabilities": [],
    })))
    return {}

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

blueprints = devices | ingested.devices
