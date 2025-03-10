import pytest
from fastapi.testclient import TestClient
from pathlib import Path
import os

@pytest.fixture(scope="session", autouse=True)
def create_assets_directory():
    """
    Create empty assets directory structure needed for the server to start.
    """
    # Create directory structure if it doesn't exist
    dist_dir = Path(__file__).resolve().parent.parent / "web" / "dist"
    assets_dir = dist_dir / "assets"
    os.makedirs(assets_dir, exist_ok=True)

@pytest.fixture
def client():
    """
    Create a FastAPI test client.
    """
    # Import app only after directory structure is created
    from saci.webui.web import app
    return TestClient(app)

def test_server_starts(client):
    """
    Test that the FastAPI server starts successfully.
    """
    response = client.get("/api/blueprints")
    assert response.status_code == 200