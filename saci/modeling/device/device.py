
class Device:
    def __init__(self, name=None, components=None, component_graph=None):
        self.name = name
        self.components = components or []
        self.component_graph = component_graph
