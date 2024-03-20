from .component import Component


class Telemetry(Component):
    def __init__(self, **kwargs):
        super().__init__(receives_external_signals=True, **kwargs)
