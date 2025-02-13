from __future__ import annotations
from dataclasses import dataclass
from collections import defaultdict
from enum import StrEnum
import asyncio
import logging

import json
import time
import importlib
from io import StringIO
from pathlib import Path
import os
from typing import Annotated, Optional

import httpx

# from flask import Flask, render_template, send_file, request, abort
from fastapi import FastAPI, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from websockets.asyncio.client import connect as ws_connect, ClientConnection as WsClientConnection
from websockets.exceptions import InvalidStatus as WsInvalidStatus, ConnectionClosedOK as WsConnectionClosedOK

from saci.modeling.device.control.controller import Controller
from saci.modeling.device.sensor.compass import CompassSensor
from saci.modeling.device.esc import ESC
from saci.modeling.device.motor.steering import Steering
from saci.modeling.device.webserver import WebServer

from ..deserializer import ingest
from .scheduling import add_search, start_work_thread, SEARCHES
from ..modeling import Device, ComponentBase
from ..modeling.device import Wifi, Motor, GPSReceiver

l = logging.getLogger(__name__)

start_work_thread()

app = FastAPI()

SACI_ROOT = Path(__file__).resolve().parent.parent.parent

### Endpoints for the frontend UI

app.mount("/assets", StaticFiles(directory=str(SACI_ROOT/"web"/"dist"/"assets")), name="assets")

@app.get("/")
async def serve_frontend_root():
    return FileResponse(str(SACI_ROOT/"web"/"dist"/"index.html"))

### Endpoints for blueprint management

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
    entry_component: Optional[ComponentID]
    exit_component: Optional[ComponentID]

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

@app.post("/api/blueprints/{bp_id}")
def create_or_update_blueprint(bp_id: str, serialized: dict, response: Response):
    if not bp_id.isidentifier():
        err = "Blueprint ID is not a valid Python identifier (this restriction will be removed in the future"
        raise HTTPException(status_code=400, detail=err)

    try:
        ingest(serialized, INGESTION_DIR / bp_id, force=True)

        if bp_id in blueprints:
            # TODO: actually check to make sure this is actually a fast-forwarded version
            created = False
        else:
            created = True
    except ValueError as e:
        l.warning(f"got deserialization error {e} when attempting to ingest blueprint")
        raise HTTPException(status_code=400, detail="Couldn't deserialize provided blueprint")

    importlib.invalidate_caches()
    # TODO: probably don't need to reload *all* the ingested modules
    importlib.reload(ingested)
    blueprints[bp_id] = ingested.devices[bp_id]
    
    if created:
        response.status_code = status.HTTP_201_CREATED

    return {}

@app.post("/api/ingest_blueprint")
def ingest_blueprint_legacy(name: str, serialized: dict, force: bool = False):
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
    blueprint_id = name
    device = ingested.devices[blueprint_id]
    blueprints[blueprint_id] = device

    return {"id": blueprint_id, "name": device.name}

### Endpoints for launching analyses using app-controller

APP_CONTROLLER_URL = os.environ.get("APP_CONTROLLER_URL", "http://localhost:3000")

def kill_all_apps():
    apps_resp = httpx.get(f"{APP_CONTROLLER_URL}/api/app")
    for app_json in apps_resp.json():
        app_id = app_json['id']
        l.info(f"killing app {app_id}")
        httpx.post(f"{APP_CONTROLLER_URL}/api/app/{app_id}/stop")
        httpx.delete(f"{APP_CONTROLLER_URL}/api/app/{app_id}")

# kill all existing apps when we start. we should probably not have this behavior permanently
try:
    kill_all_apps()
except httpx.ConnectError:
    l.warning("can't connect to app-controller, is it up and the URL configured correctly?")

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
    images: list[str]

    def as_appconfig(self):
        return {
            "name": "app",
            "interaction_model": self.interaction_model,
            "images": self.images,
            "always_pull_images": False,
        }

AnalysisID = str

@app.get("/api/blueprints/{bp_id}/analyses")
def get_analyses(bp_id: str) -> dict[AnalysisID, AnalysisUserInfo]:
    # for now ignore bp_id, but eventually analyses will be available per-device or something.
    # return mapping of analysis ID to analysis info
    return {id_: analysis.user_info for id_, analysis in analyses.items()}

@app.post("/api/blueprints/{bp_id}/analyses/{analysis_id}/launch")
async def launch_analysis(bp_id: str, analysis_id: str) -> int:
    if analysis_id not in analyses:
        raise HTTPException(status_code=400, detail="analysis not found")
    analysis = analyses[analysis_id]
    async with httpx.AsyncClient() as client:
        create_resp = await client.post(f"{APP_CONTROLLER_URL}/api/app", json=analysis.as_appconfig())
        if not create_resp.is_success:
            print(f"got error {create_resp.text} when trying to create analysis")
            raise HTTPException(status_code=500, detail="couldn't create analysis")
        app = create_resp.json()
        start_resp = await client.post(f"{APP_CONTROLLER_URL}/api/app/{app['id']}/start")
        if not start_resp.is_success:
            raise HTTPException(status_code=500, detail="couldn't start analysis")
        return app['id']

async def ws_proxy_to(ws1: WebSocket, ws2: WsClientConnection):
    while True:
        buf = await ws1.receive_bytes()
        await ws2.send(buf)

async def ws_proxy_from(ws1: WebSocket, ws2: WsClientConnection):
    async for buf in ws2:
        if not isinstance(buf, bytes):
            raise ValueError("should only get bytes in this websocket proxy")
        await ws1.send_bytes(buf)

# when deployed we should have nginx handle this proxying, but in development it's convenient to have just this one
# server handling everything. this is certainly not very performant but hopefully it's good enough for a dev proxy.
@app.websocket("/api/vnc")
async def vnc_proxy(*, websocket: WebSocket, app_id: int):
    try:
        async with httpx.AsyncClient() as client:
            addr_resp = await client.get(f"{APP_CONTROLLER_URL}/api/app/{app_id}/addr")
            if addr_resp.status_code == 404:
                raise HTTPException(status_code=404, detail="couldn't find app")
            if not addr_resp.is_success:
                raise HTTPException(status_code=500, detail="failure trying to find app")
            addr = addr_resp.json()
        ws_url = f"ws://{addr['ip']}:{addr['port']}/websockify"
        print(ws_url)
        connected = False
        while not connected:
            try:
                async with ws_connect(ws_url) as app_websocket:
                    connected = True
                    await websocket.accept()
                    async with asyncio.TaskGroup() as tg:
                        _to_task = tg.create_task(ws_proxy_to(websocket, app_websocket))
                        _from_task = tg.create_task(ws_proxy_from(websocket, app_websocket))
            except ConnectionRefusedError:
                print("host not up yet...")
                await asyncio.sleep(1)
    except* WsInvalidStatus:
        raise HTTPException(status_code=404, detail="no such app")
    except* WsConnectionClosedOK:
        pass
    except* WebSocketDisconnect as e:
        _, rest = e.split(lambda e: isinstance(e, WebSocketDisconnect) and e.code in (1000, 1001, 1005))
        if rest is not None:
            raise rest

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

analyses: dict[AnalysisID, Analysis] = {
    "taveren_model": Analysis(
        user_info=AnalysisUserInfo(
            name="Model: Ta'veren Controller",
            # TODO: hackyyyyy... should either give the different controllers different names or have some nice query mechanism
            components_included=[
                comp_id(_find_comps(rover, WebServer)[0]),
                comp_id(_find_comps(rover, Controller)[0]),
            ],
        ),
        interaction_model=InteractionModel.X11,
        images=["taveren:latest"],
    ),
    "binsync_re": Analysis(
        user_info=AnalysisUserInfo(
            name="Model: BinSync-enabled RE",
            components_included=[comp_id(_find_comps(rover, Controller)[0])],
        ),
        interaction_model=InteractionModel.X11,
        images=["ghcr.io/twizmwazin/app-controller/firefox-demo:latest"],
    ),
    "hybrid_automata": Analysis(
        user_info=AnalysisUserInfo(
            name="Model: Hybrid Automata",
            components_included=[
                comp_id(comp) for comp in _find_comps(rover, Controller)
            ] + [
                comp_id(_find_comp(rover, GPSReceiver)),
                comp_id(_find_comp(rover, CompassSensor)),
                comp_id(_find_comp(rover, Steering)),
                comp_id(_find_comp(rover, ESC)),
                comp_id(_find_comp(rover, Motor)),
            ],
        ),
        interaction_model=InteractionModel.X11,
        images=["ghcr.io/twizmwazin/app-controller/firefox-demo:latest"],
    ),
    "gazebo_hybrid_automata": Analysis(
        user_info=AnalysisUserInfo(
            name="Co-Simulation: Gazebo + Hybrid Automata",
            components_included=[
                comp_id(comp) for comp in _find_comps(rover, Controller)
            ] + [
                comp_id(_find_comp(rover, GPSReceiver)),
                comp_id(_find_comp(rover, CompassSensor)),
                comp_id(_find_comp(rover, Steering)),
                comp_id(_find_comp(rover, ESC)),
                comp_id(_find_comp(rover, Motor)),
            ],
        ),
        interaction_model=InteractionModel.X11,
        images=["quinn-controller:latest", "quinn-gazebo:latest"],
    ),
    "gazebo_firmware": Analysis(
        user_info=AnalysisUserInfo(
            name="Co-Simulation: Gazebo + Firmware",
            components_included=[
                comp_id(comp) for comp in _find_comps(rover, Controller)
            ] + [
                comp_id(_find_comp(rover, GPSReceiver)),
                comp_id(_find_comp(rover, CompassSensor)),
                comp_id(_find_comp(rover, Steering)),
                comp_id(_find_comp(rover, ESC)),
                comp_id(_find_comp(rover, Motor)),
            ],
        ),
        interaction_model=InteractionModel.X11,
        images=["onex:latest"],
    ),
}

hypotheses: dict[BlueprintID, dict[HypothesisID, HypothesisModel]] = defaultdict(dict, {
    "ngcrover": {
        "webserver_stop": HypothesisModel(
            name="From the webserver, stop the rover.",
            entry_component=comp_id(_find_comp(rover, Wifi)),
            exit_component=comp_id(_find_comp(rover, Motor)),
        ),
        "emi_compass": HypothesisModel(
            name="Using EMI, influence the compass to affect the mission.",
            entry_component=comp_id(_find_comp(rover, CompassSensor)),
            exit_component=None,
        ),
        "wifi_rollover": HypothesisModel(
            name="Over WiFi, subvert the control system to roll the rover.",
            entry_component=comp_id(_find_comp(rover, Wifi)),
            exit_component=comp_id(_find_comp(rover, Steering)),
        ),
    },
})
