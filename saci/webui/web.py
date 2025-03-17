import asyncio
import logging
import uuid

import importlib
from pathlib import Path
import os

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session, raiseload, selectinload

from fastapi import FastAPI, HTTPException, Response, WebSocket, WebSocketDisconnect, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from websockets.asyncio.client import connect as ws_connect, ClientConnection as WsClientConnection
from websockets.exceptions import InvalidStatus as WsInvalidStatus, ConnectionClosedOK as WsConnectionClosedOK
from pydantic import ValidationError

import saci.webui.data as data
import saci.webui.db as db
from saci.modeling.device import Device
from saci.modeling.state.global_state import GlobalState
from saci.webui.excavate_import import System
from saci.webui.web_models import AnalysisID, AnalysisUserInfo, AnnotationID, AnnotationModel, BlueprintID, CPVModel, CPVResultModel, ComponentTypeID, ComponentTypeModel, DeviceModel, HypothesisID, HypothesisModel, ParameterTypeModel
from saci_db.cpvs import CPVS

from ..orchestrator import identify
from ..identifier import IdentifierCPV
from ..deserializer import ingest

l = logging.getLogger(__name__)
l.setLevel(logging.DEBUG)

db.init_db()
app = FastAPI()

SACI_ROOT = Path(__file__).resolve().parent.parent.parent

### Endpoints for the frontend UI

app.mount("/assets", StaticFiles(directory=str(SACI_ROOT/"web"/"dist"/"assets")), name="assets")

@app.get("/")
async def serve_frontend_root():
    return FileResponse(str(SACI_ROOT/"web"/"dist"/"index.html"))

### Endpoints for blueprint management

@app.get('/api/blueprints')
def get_blueprints() -> dict[BlueprintID, DeviceModel]:
    # TODO: eventually we won't want to send all this data at once
    with db.get_session() as session:
        db_devices = session.query(db.Device).all()
        return {device.id: device.to_web_model() for device in db_devices}


@app.post("/api/blueprints/{bp_id}")
def create_or_update_blueprint(bp_id: str, serialized: dict, response: Response):
    try:
        blueprint = System(**serialized)
    except ValidationError:
        raise HTTPException(status_code=400, detail="Malformed blueprint")

    with db.get_session() as session, session.begin():
        session.add(blueprint.to_db_device(bp_id))

    response.status_code = status.HTTP_201_CREATED
    return {}


@app.post("/api/blueprints/{bp_id}/annotation")
def create_annotation(bp_id: str, annot_model: AnnotationModel, response: Response) -> AnnotationID:
    with db.get_session() as session:
        with session.begin():
            # Make sure the attack surface actually exists and is part of the specified device
            attack_surface = session.get(db.Component, annot_model.attack_surface)
            if attack_surface is None:
                raise HTTPException(status_code=400, detail="Attack surface component does not exist")
            if attack_surface.device_id != bp_id:
                raise HTTPException(status_code=400, detail="Attack surface component is not part of the specified device")
            annot_db = db.Annotation.from_web_model(annot_model, bp_id)
            session.add(annot_db)
        annot_id = annot_db.id

    response.status_code = status.HTTP_201_CREATED
    return annot_id

def fetch_saci_device(session: Session, bp_id: str) -> Device:
    db_device = session.execute(select(db.Device)\
                                .where(db.Device.id == bp_id)\
                                .options(selectinload(db.Device.components),
                                         selectinload(db.Device.connections),
                                         raiseload("*")))\
                       .scalar()
    if db_device is None:
        raise HTTPException(status_code=404, detail="Blueprint not found")
    return db_device.to_saci_device()

@app.get("/api/blueprints/{bp_id}/cpvs")
def identify_cpvs(bp_id: str) -> list[CPVResultModel]:
    with db.get_session() as session:
        cps = fetch_saci_device(session, bp_id)

    # TODO: re-introduce the queueing model once this takes more time
    initial_state = GlobalState(cps.components)
    return [
        CPVResultModel.from_cpv_result(cpv, path)
        for cpv in CPVS
        if (paths := identify(cps, initial_state, cpv_model=cpv)[1]) is not None
        for path in paths
    ]

@app.post("/api/blueprints/{bp_id}/hypotheses")
def create_hypothesis(bp_id: str, hypothesis_model: HypothesisModel, response: Response) -> HypothesisID:
    if bp_id not in data.blueprints:
        raise HTTPException(status_code=404, detail="Blueprint not found")

    with db.get_session() as session:
        with session.begin():
            # Fetch the device to make sure it exists and to use in validation
            device = session.execute(select(db.Device)\
                                     .where(db.Device.id == bp_id)\
                                     .options(selectinload(db.Device.components),
                                              selectinload(db.Device.annotations),
                                              raiseload("*")))\
                            .scalar()
            if device is None:
                raise HTTPException(status_code=404, detail="Blueprint not found")

            # Validate that the parts of the hypothesis specified exist in a valid state
            if (bad_comps := set(hypothesis_model.path) - {comp.id for comp in device.components}) != set():
                raise HTTPException(status_code=400, detail={
                    "message": "Components specified are not part of device specified",
                    "invalid_components": list(bad_comps),
                })
            hypothesis_annotations = set(hypothesis_model.annotations)
            if (bad_annots := hypothesis_annotations - {annot.id for annot in device.components}) != set():
                raise HTTPException(status_code=400, detail={
                    "message": "Annotations specified are not part of device specified",
                    "invalid_annotations": list(bad_annots),
                })
            if (bad_annots := {annot.id for annot in device.annotations if annot.hypothesis_id is not None}) != set():
                raise HTTPException(status_code=400, detail={
                    "message": "Annotations specified are not all unassigned to hypotheses",
                    "invalid_annotations": list(bad_annots),
                })

            # Create the hypothesis in the DB
            hypot_db = db.Hypothesis(
                device_id=bp_id,
                name=hypothesis_model.name,
                path=hypothesis_model.path,
                annotations=[annot for annot in device.annotations if annot.id in hypothesis_annotations],
            )
            session.add(hypot_db)

        hypot_id = hypot_db.id

    response.status_code = status.HTTP_201_CREATED
    return hypot_id

@app.get("/api/blueprints/{bp_id}/hypotheses/{hypot_id}/cpvs")
def hypothesis_cpvs(bp_id: str, hypot_id: HypothesisID) -> list[CPVModel]:
    with db.get_session() as session:
        device = fetch_saci_device(session, bp_id)
        db_hypot = session.execute(select(db.Hypothesis)\
                                 .where(db.Hypothesis.id == hypot_id)\
                                 .where(db.Hypothesis.device_id == bp_id)\
                                 .options(selectinload(db.Hypothesis.annotations),
                                          raiseload("*")))\
                        .scalar()
        if db_hypot is None:
            raise HTTPException(status_code=404, detail="Hypothesis not found")
        hypot = db_hypot.to_saci_hypothesis()

    identifier = IdentifierCPV(device, GlobalState(device.components))
    matched_cpvs = [cpv for cpv in CPVS if identifier.check_hypothesis(cpv, hypot)]

    return [CPVModel.from_cpv(cpv) for cpv in matched_cpvs]

@app.get("/api/components/")
def list_component_types() -> list[ComponentTypeID]:
    return list(data.all_component_types)


@app.get("/api/components/{type_id}")
def component_type_details(type_id: str) -> ComponentTypeModel:
    if (comp_type := data.all_component_types.get(type_id)) is None:
        raise HTTPException(status_code=404, detail="No component type with that ID")
    return ComponentTypeModel(
        # TODO: have component types have better human-readable names
        name=comp_type.__name__,
        # TODO: have parameters have more metadata associated with them
        parameters={name: ParameterTypeModel(type_=type_.__name__, description="coming soon") for name, type_ in comp_type.parameter_types.items()},
        ports={},
    )

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



@app.get("/api/blueprints/{bp_id}/analyses")
def get_analyses(bp_id: str) -> dict[AnalysisID, AnalysisUserInfo]:
    # for now ignore bp_id, but eventually analyses will be available per-device or something.
    # return mapping of analysis ID to analysis info
    return {id_: analysis.user_info for id_, analysis in data.analyses.items()}

@app.post("/api/blueprints/{bp_id}/analyses/{analysis_id}/launch")
async def launch_analysis(bp_id: str, analysis_id: str) -> int:
    if analysis_id not in data.analyses:
        raise HTTPException(status_code=400, detail="analysis not found")
    analysis = data.analyses[analysis_id]
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
