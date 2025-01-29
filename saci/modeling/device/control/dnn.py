from saci.modeling.device.component import (
    CyberComponentHigh,
    CyberComponentAlgorithmic,
    CyberComponentBase,
    CyberComponentSourceCode,
    CyberComponentBinary
)
from saci.modeling.device.component.cyber.cyber_abstraction_level import CyberAbstractionLevel
import claripy
import logging

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction (Cyber) ===================

class DNNHigh(CyberComponentHigh):

    __slots__ = CyberComponentHigh.__slots__ + ("known_source", "known_weight", "is_trusted", "variables",)

    def __init__(self, known_source=None, known_weight=None, is_trusted=True, **kwargs):
        """
        :param known_source: Verified source of the DNN model.
        :param known_weight: Verified weights used in the DNN.
        :param is_trusted: Boolean flag indicating if the DNN model is trusted.
        """
        super().__init__(**kwargs)
        self.known_source = known_source
        self.known_weight = known_weight
        self.is_trusted = is_trusted

        # Symbolic variables for AI security testing
        self.variables = {
            "dnn_model_integrity": claripy.BVS("dnn_model_integrity", 8),  # Model integrity status
            "dnn_adversarial_attack_flag": claripy.BVS("dnn_adversarial_attack_flag", 8),  # Adversarial attack detection
            "dnn_bias_flag": claripy.BVS("dnn_bias_flag", 8),  # Bias detection in the model
        }

    @property
    def parameter_types(self):
        return {
            "known_source": str,
            "known_weight": str,
            "is_trusted": bool,
        }


# =================== Algorithmic Abstraction (Cyber) ===================

class DNNAlgorithmic(CyberComponentAlgorithmic):

    __slots__ = CyberComponentAlgorithmic.__slots__ + ("known_source", "known_weight", "adversarial_defense", "variables",)

    def __init__(self, known_source=None, known_weight=None, adversarial_defense=True, **kwargs):
        """
        :param known_source: Verified source of the DNN model.
        :param known_weight: Verified weights used in the DNN.
        :param adversarial_defense: Boolean indicating if the model has adversarial defense.
        """
        super().__init__(**kwargs)
        self.known_source = known_source
        self.known_weight = known_weight
        self.adversarial_defense = adversarial_defense

        # Symbolic execution variables for AI security
        self.variables = {
            "dnn_confidence_score": claripy.BVS("dnn_confidence_score", 32),  # Model prediction confidence
            "dnn_training_data_integrity": claripy.BVS("dnn_training_data_integrity", 8),  # Data integrity flag
            "dnn_inference_latency": claripy.BVS("dnn_inference_latency", 32),  # Latency in inference
            "dnn_adversarial_robustness": claripy.BVS("dnn_adversarial_robustness", 8),  # Robustness against adversarial attacks
        }

    @property
    def parameter_types(self):
        return {
            "known_source": str,
            "known_weight": str,
            "adversarial_defense": bool,
        }


# =================== Full DNN Model Abstraction (Cyber) ===================

class DNN(CyberComponentBase):

    __slots__ = ("ABSTRACTIONS", "has_external_input", "known_source", "known_weight", "adversarial_defense", "variables",)

    def __init__(self, has_external_input=False, known_source=None, known_weight=None, adversarial_defense=True, **kwargs):
        """
        :param has_external_input: Boolean indicating if the model accepts external input.
        :param known_source: Verified model source.
        :param known_weight: Verified model weights.
        :param adversarial_defense: Boolean indicating if the model has adversarial defense enabled.
        """
        super().__init__(**kwargs)
        
        self.has_external_input = has_external_input
        self.known_source = known_source
        self.known_weight = known_weight
        self.adversarial_defense = adversarial_defense

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: DNNHigh(
                known_source=known_source, known_weight=known_weight, is_trusted=True
            ),
            CyberAbstractionLevel.ALGORITHMIC: DNNAlgorithmic(
                known_source=known_source, known_weight=known_weight, adversarial_defense=adversarial_defense
            ),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }

    @property
    def parameter_types(self):
        return {
            "known_source": str,
            "known_weight": str,
            "adversarial_defense": bool,
            "has_external_input": bool,
        }

######################################################    OLD VERSION    ########################################################################


# from saci.modeling.device.component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberComponentSourceCode, CyberComponentBinary
# from saci.modeling.device.component.cyber.cyber_abstraction_level import CyberAbstractionLevel

# class DNNHigh(CyberComponentHigh):
#     __slots__ = CyberComponentHigh.__slots__ + ("known_source", "known_weight")

#     def __init__(self, known_source=None, known_weight=None, **kwargs):
#         super().__init__(**kwargs)
#         self.known_source = known_source
#         self.known_weight = known_weight


# class DNNAlgorithmic(CyberComponentAlgorithmic):
#     __slots__ = CyberComponentAlgorithmic.__slots__ + ("known_source", "known_weight")

#     def __init__(self, known_source=None, known_weight=None, **kwargs):
#         super().__init__(**kwargs)
#         self.known_source = known_source
#         self.known_weight = known_weight


# class DNN(CyberComponentBase):
#     __slots__ = ("ABSTRACTIONS", "has_external_input", "known_source", "known_weight")

#     def __init__(self, has_external_input=False, known_source=None, known_weight=None, **kwargs):
#         super().__init__(**kwargs)
        
#         self.has_external_input = has_external_input
#         self.known_source = known_source
#         self.known_weight = known_weight

#         self.ABSTRACTIONS = {
#             CyberAbstractionLevel.HIGH: DNNHigh(known_source=known_source, known_weight=known_weight),
#             CyberAbstractionLevel.ALGORITHMIC: DNNAlgorithmic(known_source=known_source, known_weight=known_weight),
#             CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
#             CyberAbstractionLevel.BINARY: CyberComponentBinary(),
#         }