import pytest
from fastapi.testclient import TestClient
from pathlib import Path
import os
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

def test_server_starts(client):
    """
    Test that the FastAPI server starts successfully.
    """
    response = client.get("/api/blueprints")
    assert response.status_code == 200