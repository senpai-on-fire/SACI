from .cyber_abstraction_level import CyberAbstractionLevel


class ComponentBase:
    STATE_ATTR = ()

    def __init__(self, name=None, abstraction=CyberAbstractionLevel.UNKNOWN, linked_abstractions=None):
        self.name = name
        self.abstraction_level = abstraction
        self.linked_abstractions = linked_abstractions or {}
