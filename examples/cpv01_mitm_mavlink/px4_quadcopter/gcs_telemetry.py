import networkx as nx

from saci.modeling import Telemetry


class GCSTelemetry(Telemetry):
    S_RECV = "recv"
    S_SEND = "send"
    S_PROCESSING = "processing"
    S_NOTIFY = "notify"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.state_graph = nx.from_edgelist([
            (self.S_RECV, self.S_PROCESSING),
            (self.S_PROCESSING, self.S_SEND),
            (self.S_PROCESSING, self.S_NOTIFY),
            (self.S_SEND, self.S_RECV),
        ], create_using=nx.DiGraph)
