import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import saci


@pytest.fixture(scope="session", autouse=True)
def create_assets_directory():
    """
    Create empty assets directory structure needed for the server to start.
    """
    # Create directory structure at project root
    project_root = Path(__file__).resolve().parent.parent
    dist_dir = project_root / "web" / "dist"
    assets_dir = dist_dir / "assets"
    os.makedirs(assets_dir, exist_ok=True)

    # Also create directory at the installed package location
    package_path = Path(saci.__file__).resolve().parent.parent
    package_assets_dir = package_path / "web" / "dist" / "assets"
    os.makedirs(package_assets_dir, exist_ok=True)

    # For good measure, print both paths to help with debugging
    print(f"Created assets directory at project root: {assets_dir}")
    print(f"Created assets directory at package location: {package_assets_dir}")


@pytest.fixture
def client():
    """
    Create a FastAPI test client.
    """
    # Import app only after directory structure is created
    from saci.webui.web import app

    return TestClient(app)


@pytest.fixture
def bp_id():
    """A valid blueprint ID.

    For now this is statically just the ngcrover blueprint, but in the database-based future, we may have to create a
    fresh one, so this is abstracted out in anticipation.

    """
    return "ngcrover"


def test_server_starts(client):
    """
    Test that the FastAPI server starts successfully.
    """
    response = client.get("/api/blueprints")
    assert response.status_code == 200


def test_ngcrover_blueprint_exists(client):
    """Make sure the "ngcrover" blueprint exists and some basic properties of it hold. This will probably have to change
    once we finish the move to an actually database-driven data model.

    """

    blueprints = client.get("/api/blueprints").json()

    assert "ngcrover" in blueprints
    ngcrover = blueprints["ngcrover"]

    # Component IDs aren't guaranteed to be stable, but the names of the component types should be
    component_names = {comp["name"] for comp in ngcrover["components"].values()}
    assert "WebServer" in component_names
    assert "Motor" in component_names


def test_create_annotation(client, bp_id):
    """Test annotation creation and recall."""

    blueprint = client.get("/api/blueprints").json()[bp_id]

    comp_id = next(iter(blueprint["components"]))
    effect = "foo"
    attack_model = "bar"
    annotation = {
        "attack_surface": comp_id,
        "effect": effect,
        "attack_model": attack_model,
    }

    # Create a new annotation
    response = client.post(f"/api/blueprints/{bp_id}/annotations", json=annotation)
    assert 200 <= response.status_code < 300
    annot_id = response.json()

    # Check to make sure we get the new annotation back in the blueprint
    new_blueprint = client.get("/api/blueprints").json()[bp_id]
    new_annotations = new_blueprint["annotations"]
    assert annot_id in new_annotations
    received_annotation = new_annotations[annot_id]
    assert received_annotation == annotation
