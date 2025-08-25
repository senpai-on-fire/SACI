import asyncio
import contextlib
import logging

from pathlib import Path
import os

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session, raiseload, selectinload

from fastapi import BackgroundTasks, FastAPI, HTTPException, Response, WebSocket, WebSocketDisconnect, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from websockets.asyncio.client import connect as ws_connect, ClientConnection as WsClientConnection
from websockets.exceptions import InvalidStatus as WsInvalidStatus, ConnectionClosedOK as WsConnectionClosedOK
from pydantic import ValidationError

from saci.modeling.annotation import Annotation
from saci.orchestrator.tool import TOOLS
import saci.webui.data as data
import saci.webui.db as db
from saci.modeling.device import Device
from saci.modeling.state.global_state import GlobalState
from saci.webui.excavate_import import System
from saci.webui.web_models import (
    AnalysisID,
    AnalysisUserInfo,
    AnnotationID,
    AnnotationModel,
    BlueprintID,
    CPVModel,
    CPVResultModel,
    ComponentTypeID,
    ComponentTypeModel,
    DeviceModel,
    HypothesisID,
    HypothesisModel,
    ParameterTypeModel,
)
from saci_db.cpvs import CPVS

from ..orchestrator import identify
from ..identifier import IdentifierCPV

l = logging.getLogger(__name__)
l.setLevel(logging.DEBUG)

APP_CONTROLLER_URL = os.environ.get("APP_CONTROLLER_URL", "http://localhost:3000")


async def kill_apps(app_ids: list[int], client: httpx.AsyncClient | None = None):
    cm: contextlib.nullcontext[httpx.AsyncClient] | httpx.AsyncClient
    if client is None:
        cm = httpx.AsyncClient()
    else:
        cm = contextlib.nullcontext(client)

    async with cm as c:
        for app_id in app_ids:
            l.info(f"killing app {app_id}")
            await c.post(f"{APP_CONTROLLER_URL}/api/app/{app_id}/stop")
            await c.delete(f"{APP_CONTROLLER_URL}/api/app/{app_id}")


async def get_running_app_ids(client: httpx.AsyncClient) -> list[int]:
    apps_resp = await client.get(f"{APP_CONTROLLER_URL}/api/app")
    return [app_json["id"] for app_json in apps_resp.json()]


async def kill_all_apps():
    async with httpx.AsyncClient() as client:
        await kill_apps(await get_running_app_ids(client), client=client)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    # kill all existing apps when we start. we should probably not have this behavior permanently
    num_retries = 20
    delay_time = 0.1
    for i in range(num_retries):
        try:
            await kill_all_apps()
            break
        except httpx.ConnectError:
            if i == 0:
                l.info(
                    "don't see app-controller up yet at %r, will try %d more times with %fs between them",
                    APP_CONTROLLER_URL,
                    num_retries,
                    delay_time,
                )
            await asyncio.sleep(delay_time)
    else:
        l.warning("don't see app-controller up at %r after %d retries, ignoring", APP_CONTROLLER_URL, num_retries)

    yield


db.init_db()
app = FastAPI(lifespan=lifespan)

SACI_ROOT = Path(__file__).resolve().parent.parent.parent

### Endpoints for the frontend UI

app.mount("/assets", StaticFiles(directory=str(SACI_ROOT / "web" / "dist" / "assets")), name="assets")


@app.get("/")
async def serve_frontend_root():
    return FileResponse(str(SACI_ROOT / "web" / "dist" / "index.html"))


### Endpoints for blueprint management


@app.get("/api/blueprints")
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

    if not bp_id:
        bp_id = str(blueprint.id or blueprint.name)

    with db.get_session() as session, session.begin():
        # TODO: actually update
        existing_device = session.get(db.Device, bp_id)
        if existing_device is not None:
            session.delete(existing_device)
        session.add(blueprint.to_db_device(bp_id))

    response.status_code = status.HTTP_201_CREATED
    return {}


@app.post("/api/blueprints/{bp_id}/annotations")
def create_annotation(bp_id: str, annot_model: AnnotationModel, response: Response) -> AnnotationID:
    with db.get_session() as session:
        with session.begin():
            # Make sure the attack surface actually exists and is part of the specified device
            attack_surface = session.get(db.Component, annot_model.attack_surface)
            if attack_surface is None:
                raise HTTPException(status_code=400, detail="Attack surface component does not exist")
            if attack_surface.device_id != bp_id:
                raise HTTPException(
                    status_code=400, detail="Attack surface component is not part of the specified device"
                )
            annot_db = db.Annotation.from_web_model(annot_model, bp_id)
            session.add(annot_db)
        annot_id = annot_db.id

    response.status_code = status.HTTP_201_CREATED
    return annot_id


@app.delete("/api/blueprints/{bp_id}/annotations/{annot_id}")
def delete_annotation(bp_id: str, annot_id: AnnotationID):
    with db.get_session() as session, session.begin():
        annot_db = session.get(db.Annotation, annot_id)
        if annot_db is None:
            raise HTTPException(status_code=404, detail="Annotation does not exist")
        if annot_db.device_id != bp_id:
            raise HTTPException(status_code=404, detail="Annotation is not part of given device")

        session.delete(annot_db)


def fetch_saci_db_device(
    session: Session, bp_id: str, with_annotations: bool = False, with_hypotheses: bool = False
) -> db.Device:
    options = [selectinload(db.Device.components), selectinload(db.Device.connections)]
    if with_annotations:
        options.append(selectinload(db.Device.annotations))
    if with_hypotheses:
        options.append(selectinload(db.Device.hypotheses))
    options.append(raiseload("*"))

    db_device = session.execute(select(db.Device).where(db.Device.id == bp_id).options(*options)).scalar()
    if db_device is None:
        raise HTTPException(status_code=404, detail="Blueprint not found")
    else:
        return db_device


def fetch_saci_device(session: Session, bp_id: str) -> Device:
    return fetch_saci_db_device(session, bp_id).to_saci_device()


def fetch_saci_device_and_annotations(session: Session, bp_id: str) -> tuple[Device, list[Annotation]]:
    db_device = fetch_saci_db_device(session, bp_id, with_annotations=True)
    return db_device.to_saci_device(), [annot.to_saci_annotation() for annot in db_device.annotations]


@app.get("/api/blueprints/{bp_id}/cpvs")
def identify_cpvs(bp_id: str, only_special: bool = False) -> list[CPVResultModel]:
    with db.get_session() as session:
        cps, annotations = fetch_saci_device_and_annotations(session, bp_id)

    # TODO: re-introduce the queueing model to this routine once this takes more time

    initial_state = GlobalState(cps.components)

    # TODO: the CPVPaths contain the actual ComponentBases and so hashability is fragile and dependent on being
    # identified from the same device object. we should probably make them just have the component IDs.
    annotation_vulns = [annot.into_vulnerability(cps) for annot in annotations]
    identified_cpvs = {
        (cpv, path)
        for cpv in CPVS
        if (paths := identify(cps, initial_state, cpv_model=cpv, vulns=annotation_vulns)[1]) is not None
        for path in paths
    }

    if only_special:
        bare_cpvs = {
            (cpv, path)
            for cpv in CPVS
            if (paths := identify(cps, initial_state, cpv_model=cpv)[1]) is not None
            for path in paths
        }
        identified_cpvs -= bare_cpvs

    return [CPVResultModel.from_cpv_result(cpv, path) for cpv, path in identified_cpvs]


@app.post("/api/blueprints/{bp_id}/hypotheses")
def create_hypothesis(bp_id: str, hypothesis_model: HypothesisModel, response: Response) -> HypothesisID:
    with db.get_session() as session:
        with session.begin():
            # Fetch the device to make sure it exists and to use in validation
            device = session.execute(
                select(db.Device)
                .where(db.Device.id == bp_id)
                .options(selectinload(db.Device.components), selectinload(db.Device.annotations), raiseload("*"))
            ).scalar()
            if device is None:
                raise HTTPException(status_code=404, detail="Blueprint not found")

            # Validate that the parts of the hypothesis specified exist in a valid state
            if (bad_comps := set(hypothesis_model.path) - {comp.id for comp in device.components}) != set():
                raise HTTPException(
                    status_code=400,
                    detail={
                        "message": "Components specified are not part of device specified",
                        "invalid_components": list(bad_comps),
                    },
                )
            hypothesis_annotations = set(hypothesis_model.annotations)
            if (bad_annots := hypothesis_annotations - {annot.id for annot in device.annotations}) != set():
                raise HTTPException(
                    status_code=400,
                    detail={
                        "message": "Annotations specified are not part of device specified",
                        "invalid_annotations": list(bad_annots),
                    },
                )
            if (bad_annots := {annot.id for annot in device.annotations if annot.hypothesis_id is not None}) != set():
                raise HTTPException(
                    status_code=400,
                    detail={
                        "message": "Annotations specified are not all unassigned to hypotheses",
                        "invalid_annotations": list(bad_annots),
                    },
                )

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
        db_hypot = session.execute(
            select(db.Hypothesis)
            .where(db.Hypothesis.id == hypot_id)
            .where(db.Hypothesis.device_id == bp_id)
            .options(selectinload(db.Hypothesis.annotations), raiseload("*"))
        ).scalar()
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
        parameters={
            name: ParameterTypeModel(type_=type_.__name__, description="coming soon")
            for name, type_ in comp_type.parameter_types.items()
        },
        ports={},
    )


### Endpoints for launching analyses using app-controller


@app.get("/api/blueprints/{bp_id}/analyses")
def get_analyses(bp_id: str) -> dict[AnalysisID, AnalysisUserInfo]:
    with db.get_session() as session:
        device = fetch_saci_device(session, bp_id)

    return {
        tool_id: AnalysisUserInfo(
            name=tool.name,
            components_included=[int(comp_id) for comp_id in tool.compatible_components(device)],
        )
        for tool_id, tool in TOOLS.items()
    }


@app.post("/api/blueprints/{bp_id}/analyses/{tool_id}/launch")
async def launch_analysis(bp_id: str, tool_id: str, raw_configs: list[str], background_tasks: BackgroundTasks) -> int:
    # TODO: use bp_id...
    if (tool := TOOLS.get(tool_id)) is None:
        raise HTTPException(status_code=404, detail="Analysis not found")

    if len(raw_configs) != len(tool.containers):
        raise HTTPException(status_code=400, detail="Wrong number of configurations")

    container_configs = []
    for i, (raw_config, container) in enumerate(zip(raw_configs, tool.containers)):
        try:
            config = container.config_type.model_validate_json(raw_config)
            container_configs.append(
                data.ContainerConfig(
                    image=container.image_name,
                    config=config.model_dump_json(),
                    image_pull_policy="IfNotPresent",
                )
            )
        except ValidationError as e:
            raise HTTPException(
                status_code=400,
                detail={
                    "message": f"Configuration #{i} did not validate",
                    "validation_error": str(e),
                },
            )

    async with httpx.AsyncClient() as client:
        # SACI won't be used long term to launch analyses (in our current
        # thinking). In order to not overwhelm the server with long-running
        # analyses, we'll only support running a single analysis at once, so
        # kill all the existing analyses first.
        running_apps = await get_running_app_ids(client)
        l.debug("killing apps (in background) with IDs %r before starting new analysis", running_apps)
        background_tasks.add_task(kill_apps, running_apps)

        app_config = data.AppConfig(
            name=f"{tool.name}-{bp_id}".lower(),
            interaction_model=data.InteractionModel.X11,
            containers=container_configs,
            always_pull_images=False,
            enable_docker=False,
            autostart=True,
        )

        create_resp = await client.post(f"{APP_CONTROLLER_URL}/api/app", json=app_config.model_dump())

        if not create_resp.is_success:
            print(f"app_config was {app_config.model_dump_json()}")
            print(f"got error {create_resp.text} when trying to create analysis")
            raise HTTPException(status_code=500, detail="couldn't create analysis")
        app = create_resp.json()

        return app["id"]


@app.get("/api/logs")
async def logs(app_id: int):
    async with httpx.AsyncClient() as client:
        logs_resp = await client.get(f"{APP_CONTROLLER_URL}/api/app/{app_id}/output/0")
        return logs_resp.text


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
