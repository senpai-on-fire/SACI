import argparse
import json
import string
import dataclasses
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar

import networkx as nx
from jinja2 import Environment

from saci.modeling.device.component.component_base import ComponentBase


@dataclass(frozen=True)
class ComponentPath:
    """The path to, and name of, a component class.

    Basically
        from `module_path` import `class_name`
    should be valid.
    """

    module_path: str
    class_name: str
    attr_name: str
    local: bool = False
    """True when this component is being generated here."""
    file_name: str | None = None
    """Present when this component is being generated here."""

    @property
    def qualified_class_name(self) -> str:
        return self.module_path.lstrip(".") + "." + self.class_name

    @property
    def import_statement(self) -> str:
        if self.local:
            return f"from .{self.module_path} import {self.class_name}"
        else:
            return f"from {self.module_path} import {self.class_name}"


# TODO: probably have this in some more centralized location
BUILTIN_SYSTEM_COMPONENTS: dict[str, ComponentPath] = {
    "Compass": ComponentPath("saci.modeling.device", "CompassSensorHigh", "compass"),
    "GPS": ComponentPath("saci.modeling.device", "GPSReceiver", "gps"),
    "Vehicle Control": ComponentPath("saci.modeling.device", "Controller", "vehicle_control"),
    "Drive Motor Control": ComponentPath("saci.modeling.device", "Controller", "drive_motor_control"),
}

# TODO: dedup this code with that in saci.web.data, or better yet replace with a better solution
T = TypeVar("T")


def _all_subclasses(c: type[T]) -> list[type[T]]:
    return [c] + [subsubc for subc in c.__subclasses__() for subsubc in _all_subclasses(subc)]


# TODO: janky
saci_type_mapping: dict[str, ComponentPath] = {}
for comp_type in _all_subclasses(ComponentBase):
    name = comp_type.__qualname__
    saci_type_mapping[name] = ComponentPath(
        comp_type.__module__,
        name,
        name.lower(),
    )


def split_any(s: str, split_on: set[str]) -> list[str]:
    out = []
    part = ""
    for c in s:
        if c in split_on:
            if part != "":
                out.append(part)
                part = ""
        else:
            part += c
    if part != "":
        out.append(part)
    return out


def system_name_to_path(system_name: str, saci_type: str) -> ComponentPath:
    # if system_name in BUILTIN_SYSTEM_COMPONENTS:
    #     return BUILTIN_SYSTEM_COMPONENTS[system_name]
    if system_name[0] in string.digits:
        system_name = "N" + system_name
    name_parts = split_any(system_name, {" ", "-", "_"})
    module_name = "".join(part.lower() for part in name_parts)
    attr_name = "comp_" + "_".join(part.lower() for part in name_parts)
    class_name = "".join(name_parts)
    if any(not name.isidentifier() for name in (module_name, class_name, attr_name)):
        raise ValueError(f"Couldn't convert system name {system_name!r} to valid names")
    if (path := saci_type_mapping.get(saci_type)) is not None:
        return dataclasses.replace(path, attr_name=attr_name)
    return ComponentPath(module_name, class_name, attr_name, local=True, file_name=f"{module_name}.py")


@dataclass(frozen=True)
class Port:
    name: str
    # TODO: refine connections type
    connections: list[dict]
    unique_instance_id: str


@dataclass
class System:
    id_: int
    name: str
    subsystems: list["System"]
    ports: list[Port]
    interfaces: list[dict]
    saci_type: str

    @property
    def all_subsystems(self):
        return [subsub for sub in self.subsystems for subsub in [sub] + sub.all_subsystems]

    @property
    def parent_child_edges(self):
        return [(self.name, child.name) for child in self.subsystems] + [
            edge for child in self.subsystems for edge in child.parent_child_edges
        ]

    def __repr__(self):
        return self.name

    def __hash__(self):
        return hash(self.id_)


class Deserializer:
    # TODO: refine types
    ports: dict[str, System]
    interfaces: list[tuple[tuple[str, str], tuple[str, str]]]

    def __init__(self):
        self.ports = {}
        self.interfaces = []
        self.system_names = set()
        self._unnamed_port_counter = 0

    def deserialize_port(self, node: dict):
        name = node["name"]
        if not name:
            name = f"port{self._unnamed_port_counter}"
            self._unnamed_port_counter += 1
        return Port(name, node["connections"], node["unique_instance_id"])

    def deserialize_system(self, node):
        # if ifaces := node["interfaces"]:
        #     print(f"{node["name"]}'s interfaces: {ifaces}")
        # if components := node["node_data"]:
        #     print(f"{node["name"]}'s node_data: {components}")
        subsystems = [self.deserialize_system(subnode) for subnode in node["systems"]]
        ports = [self.deserialize_port(port_node) for port_node in node["ports"]]
        name = node["name"]
        while name in self.system_names:
            name += "p"
        self.system_names.add(name)
        sys = System(
            node["id"],
            name,
            subsystems,
            ports,
            node["interfaces"],
            node["saciType"],
        )
        for port in ports:
            self.ports[port.unique_instance_id] = sys
        for iface in sys.interfaces:
            src = iface["src_port"]
            dst = iface["dest_port"]
            self.interfaces.append(((src["name"], src["unique_instance_id"]), (dst["name"], dst["unique_instance_id"])))
        return sys

    @property
    def connections(self):
        return [(self.ports[src].name, self.ports[dst].name) for (_, src), (_, dst) in self.interfaces]

    def render(self, render_path: Path, sys: System):
        g = nx.DiGraph()
        for subsys in [sys] + sys.all_subsystems:
            g.add_node(subsys)
        edge_labels = {}
        for (src_name, src_port), (dst_name, dst_port) in self.interfaces:
            src_sys = self.ports[src_port]
            dst_sys = self.ports[dst_port]
            # TODO: support multiple edges between the same systems...
            label = edge_labels[(src_sys, dst_sys)] = f"{src_name} -> {dst_name}"
            g.add_edge(src_sys, dst_sys, label=label)
        a = nx.nx_agraph.to_agraph(g)
        a.draw(render_path, prog="dot")
        # pos = nx.spring_layout(g)
        # nx.draw_networkx_edge_labels(g, pos, edge_labels=edge_labels)
        # plt.show()


def port_name_to_attr(port_name: str) -> str:
    name_parts = port_name.split(" ")
    attr = "_".join(part.lower() for part in name_parts)
    if attr[0].isdigit():
        attr = "N" + attr
    if not attr.isidentifier():
        raise ValueError(f"Couldn't convert port name {port_name!r} to valid attribute name")
    return attr


jinja_env = Environment(autoescape=False)
jinja_env.filters["port_name_to_attr"] = port_name_to_attr
jinja_env.filters["repr"] = repr

system_template = jinja_env.from_string("""\"""Auto-generated component for system "{{ system.name }}".\"""
from saci.modeling.device.component.cyber import CyberComponentBase

class {{ component_path.class_name }}(CyberComponentBase):
    def __init__(self, **kwargs):
        # TODO: has_external_input?
        super().__init__(**kwargs)
        # TODO: do something more interesting with ports
        {% for port in system.ports %}
        self.{{ port.name | port_name_to_attr }} = None
        {% endfor %}
""")


def emit_system(base_path: Path, system: System) -> ComponentPath:
    component_path = system_name_to_path(system.name, system.saci_type)
    if component_path.file_name is None:
        return component_path

    with open(base_path / component_path.file_name, "w") as file:
        file.write(system_template.render(system=system, component_path=component_path))

    return component_path


device_template = jinja_env.from_string("""\"""Auto-generated device for system "{{ name }}".\"""
import os
import networkx as nx
from clorm import Predicate, IntegerField

import saci.modeling.device

# TODO: dedup these imports, also check to make sure we don't have component name clashes
{% for comp_path in components.values() %}
{{ comp_path.import_statement }}
{% endfor %}


class {{ device_path.class_name }}Crash(Predicate):
    time = IntegerField()
    
class {{ device_path.class_name }}(saci.modeling.Device):
    crash_atom = {{ device_path.class_name }}Crash
    description = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'device.lp')

    def __init__(self, state=None):
        components = []
        {% for comp_name, comp_path in components.items() %}
        {{ comp_path.attr_name }} = {{ comp_path.class_name }}(name={{ comp_name | repr }})
        components.append({{ comp_path.attr_name }})
        {% endfor %}

        component_graph = nx.from_edgelist([
        {% for start_name, end_name in connections %}
            ({{ components[start_name].attr_name }}, {{ components[end_name].attr_name }}),
        {% endfor %}
        ], create_using=nx.DiGraph)

        super().__init__(
            name="{{ device_path.class_name }}",
            components=components,
            component_graph=component_graph,
            state=state,
        )
""")


def emit_device(
    base_path: Path, components: dict[str, ComponentPath], connections: list[tuple[str, str]], name: str, saci_type: str
):
    device_path = system_name_to_path(name, saci_type)  # TODO: we never want to find this in the builtins
    with open(base_path / "__init__.py", "w") as file:
        file.write(
            device_template.render(components=components, connections=connections, name=name, device_path=device_path)
        )

    with open(base_path / "device.lp", "w") as _:
        pass


def just_filter_the_json(d):
    return {
        "name": d["name"],
        "systems": [just_filter_the_json(s) for s in d["systems"]],
        # "ports": d["ports"],
        # "interfaces": d["interfaces"],
    }


def ingest(serialized: dict, output_dir: Path, render: bool = False, force: bool = False):
    if output_dir.exists():
        if not output_dir.is_dir():
            raise ValueError(f"Output location {output_dir} exists, but is not a directory")
        if not force:
            raise FileExistsError(f"Output location {output_dir} exists, won't overwrite it without force=True")
    else:
        output_dir.mkdir()

    deserializer = Deserializer()
    device = deserializer.deserialize_system(serialized)

    if render:
        deserializer.render(output_dir / "system.png", device)

    # we're treating subsystems like components for now.
    # perhaps this will change if we actually get components in the TA3 output.
    components = {}
    for sub in device.all_subsystems:
        if sub.name in components:
            # should we instead dedup somehow?
            raise ValueError(f"Non-unique system name {sub.name!r}")
        components[sub.name] = emit_system(output_dir, sub)

    # TODO: do we want to model connections to the top-level device in some better way than just filtering them out...
    connections = [(src, dst) for src, dst in deserializer.connections if src != device.name and dst != device.name] + [
        (src, dst) for src, dst in device.parent_child_edges if src != device.name
    ]
    emit_device(output_dir, components, connections, device.name, device.saci_type)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--render", action="store_true")
    parser.add_argument("serialized", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()

    with args.serialized.open() as f:
        serialized = json.load(f)

    ingest(serialized, args.output_dir, render=args.render)
