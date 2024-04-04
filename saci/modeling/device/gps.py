from .component import CyberComponentHigh, CyberComponentAlgorithmic


class GPSReceiver(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__ + ("protocol_name", "authenticated", "signal_strength_threshold")

    def __init__(self, protocol_name=None, authenticated=False, signal_strength_threshold=-100, **kwargs):
        super().__init__(has_external_input=True, **kwargs)
        self.protocol_name = protocol_name
        self.authenticated = authenticated
        self.signal_strength_threshold = signal_strength_threshold

    def is_signal_valid(self, signal_strength):
        # Determines if the received GPS signal meets the strength threshold.
        return signal_strength >= self.signal_strength_threshold


# class GPSReceiverAlgorithm(CyberComponentAlgorithmic):
#     def __init__(self, signal_strength_threshold=-100, has_anomaly_detection=False, **kwargs):
#         super().__init__(**kwargs)
#         # there exists a symbolic variable, and it is constrained by the components initialization
#         self.variables["signal_strength_threshold"] = BVS("signal_strength_threshold", 64)
#         self.variables["signal_strength_threshold"] == signal_strength_threshold
        
#         # algo:
#         # if (signal_strength >= signal_strength_threshold):
#         #     return signal 
#         # else:
#         #    return None
#         #
        
        
#         self.has_anomaly_detection = has_anomaly_detection
        
#     def position(self, communication: BaseCommunication) -> bool:
#         if not communication.src == "gps":
#             return False
#         # TODO: model navigation algorithm
#         self.condition = [0.0, 0.0, 5.0]
#         return True