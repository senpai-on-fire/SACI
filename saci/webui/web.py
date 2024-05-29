from __future__ import annotations

from flask import Flask, render_template, send_file, request

from .scheduling import add_search, start_work_thread

app = Flask(__name__)
start_work_thread()


def get_component_abstractions(comp) -> dict[str, str]:
    if hasattr(comp, "ABSTRACTIONS"):
        return dict((str(level), abs_obj.__class__.__name__) for level, abs_obj in comp.ABSTRACTIONS.items())
    return {}


@app.route('/')
def index():
    return render_template("index.html", cpvs=CPVS)


@app.route("/api/cpv_info")
def cpv_info():
    cls_name = request.args.get("name")

    if not cls_name:
        return {"error": "Name is required"}

    for cpv in CPVS:
        if cpv.__class__.__name__ == cls_name:
            break
    else:
        return {"error": "CPV not found"}

    return {
        "name": cpv.NAME,
        "components": [
            {
                "name": comp.name,
                "abstractions": get_component_abstractions(comp),
            } for comp in cpv.required_components],
    }


@app.route("/api/cpv_search")
def cpv_search():
    # TODO: Getting the components from the front end

    search_id = add_search()

    return {
        "search_id": search_id,
    }


@app.route("/index.js")
def js():
    # TODO: Serve it as a static file
    return send_file("templates/index.js")


# delayed import
from saci_db.cpvs import CPVS