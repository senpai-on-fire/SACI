from . component import Component


class Motor(Component):
    S_RUNNING = "running"
    S_STOPPED = "stopped"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

