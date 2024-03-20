import networkx as nx

from saci.modeling import Controller


class PX4Controller(Controller):
    S_ACCCEPT_NOTIF = "accept_notif"
    S_PROCESS_NOTIF = "process_notif"
    S_DISARM = "disarm"
    S_ARM = "arm"
    S_SLEEP = "sleep"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.state_graph = nx.from_edgelist([
            (self.S_ACCCEPT_NOTIF, self.S_PROCESS_NOTIF),
            (self.S_PROCESS_NOTIF, self.S_SLEEP),
            (self.S_PROCESS_NOTIF, self.S_DISARM),
            (self.S_PROCESS_NOTIF, self.S_ARM),
            (self.S_DISARM, self.S_SLEEP),
            (self.S_ARM, self.S_SLEEP),
            (self.S_SLEEP, self.S_ACCCEPT_NOTIF),
        ], create_using=nx.DiGraph)
