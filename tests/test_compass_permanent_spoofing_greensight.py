import json
from pathlib import Path

from saci.identifier.identifier_cpv import IdentifierCPV
from saci.modeling.cpv import CPV
from saci.modeling.state import GlobalState
from saci.webui import db as dbmod
from saci.webui.excavate_import import System
from saci_db.cpvs import CompassPermanentSpoofingCPV


def assert_cpv_matches_blueprint(cpv: CPV, blueprint_filename: str):
    """Generic function to test that a CPV matches at least one path in a blueprint."""
    # Setup database
    engine = dbmod.get_engine("sqlite:///:memory:")
    dbmod.init_db(engine)
    session = dbmod.get_session(engine)

    # Load and process blueprint
    blueprint_path = Path(__file__).parent / blueprint_filename
    with open(blueprint_path) as f:
        blueprint_data = json.load(f)

    blueprint = System(**blueprint_data)
    device = blueprint.to_db_device(device_id=blueprint.name)
    assert hasattr(device, "components"), "Device must have components"

    # Save to database and convert to SACI device
    with session.begin():
        session.add(device)

    db_device = session.query(dbmod.Device).filter_by(id=blueprint.name).one()
    saci_device = db_device.to_saci_device()

    # Test CPV matching
    identifier = IdentifierCPV(saci_device, GlobalState(saci_device.components))
    matches = identifier.identify(cpv)

    print(f"Matches for {cpv.__class__.__name__}: {matches}")
    assert matches, f"{cpv.__class__.__name__} should match at least one path in the blueprint."


def test_compass_permanent_spoofing_match():
    """Test that CompassPermanentSpoofingCPV matches at least one path in the blueprint."""
    assert_cpv_matches_blueprint(CompassPermanentSpoofingCPV(), "delivery3_greensight_v1.json")
