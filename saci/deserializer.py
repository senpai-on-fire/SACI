import json
from typing import List
from dataclasses import dataclass

import networkx as nx
import matplotlib.pyplot as plt


@dataclass
class System:
    id_: int
    name: str
    systems: List["System"]
    ports: List[dict]
    interfaces: List[dict]

    @property
    def all_systems(self):
        return [subsub for sub in self.systems for subsub in [sub] + sub.all_systems]

    def __repr__(self):
        return self.name

    def __hash__(self):
        return hash(self.id_)

class Deserializer:
    def __init__(self):
        self.ports = {}
        self.interfaces = []

    def deserialize_system(self, node):
        # if ifaces := node["interfaces"]:
        #     print(f"{node["name"]}'s interfaces: {ifaces}")
        # if components := node["node_data"]:
        #     print(f"{node["name"]}'s node_data: {components}")
        subsystems = [self.deserialize_system(subnode) for subnode in node["systems"]]
        sys = System(
            node["id"],
            node["name"],
            subsystems,
            node["ports"],
            node["interfaces"],
        )
        for port in sys.ports:
            self.ports[port["unique_instance_id"]] = sys
        for iface in sys.interfaces:
            src = iface["src_port"]
            dst = iface["dest_port"]
            self.interfaces.append(((src["name"], src["unique_instance_id"]), (dst["name"], dst["unique_instance_id"])))
        return sys

    def render(self, sys):
        g = nx.DiGraph()
        for subsys in [sys] + sys.all_systems:
            g.add_node(subsys)
        edge_labels = {}
        for (src_name, src_port), (dst_name, dst_port) in self.interfaces:
            src_sys = self.ports[src_port]
            dst_sys = self.ports[dst_port]
            # TODO: support multiple edges between the same systems...
            label = edge_labels[(src_sys, dst_sys)] = f"{src_name} -> {dst_name}"
            g.add_edge(src_sys, dst_sys, label=label)
        a = nx.nx_agraph.to_agraph(g)
        a.draw("system.png", prog="dot")
        # pos = nx.spring_layout(g)
        # nx.draw_networkx_edge_labels(g, pos, edge_labels=edge_labels)
        # plt.show()

def just_filter_the_json(d):
    return {
        "name": d["name"],
        "systems": [just_filter_the_json(s) for s in d["systems"]],
        # "ports": d["ports"],
        # "interfaces": d["interfaces"],
    }

if __name__ == '__main__':
    with open("/Users/jessie/projects/senpai/saci-database/ngc rover with db ids.json", "r") as f:
        # with open("/Users/jessie/projects/senpai/saci-database/filtered.json", "w") as f2:
        #     json.dump(just_filter_the_json(json.load(f)), f2)
        deserializer = Deserializer()
        system = deserializer.deserialize_system(json.load(f))
        deserializer.render(system)
