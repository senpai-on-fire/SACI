import logging

import claripy

from saci.modeling.device.component import (
    CyberComponentAlgorithmic,
    CyberComponentBase,
    CyberComponentBinary,
    CyberComponentHigh,
    CyberComponentSourceCode,
)
from saci.modeling.device.component.cyber.cyber_abstraction_level import CyberAbstractionLevel

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction (Cyber) ===================


class DNNTrackingHigh(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__ + (
        "known_source",
        "known_weight",
        "is_trusted",
        "object_tracking_accuracy",
        "false_positive_rate",
        "variables",
    )

    def __init__(
        self,
        known_source=None,
        known_weight=None,
        is_trusted=True,
        object_tracking_accuracy=0.95,
        false_positive_rate=0.02,
        **kwargs,
    ):
        """
        :param known_source: Verified source of the DNN model.
        :param known_weight: Verified weights used in the DNN.
        :param is_trusted: Boolean flag indicating if the DNN model is trusted.
        :param object_tracking_accuracy: Average accuracy of object tracking (0 to 1).
        :param false_positive_rate: Percentage of false detections (0 to 1).
        """
        super().__init__(**kwargs)
        self.known_source = known_source
        self.known_weight = known_weight
        self.is_trusted = is_trusted
        self.object_tracking_accuracy = object_tracking_accuracy
        self.false_positive_rate = false_positive_rate  # Helps detect dataset bias & misclassification.

        # Symbolic variables for AI security testing
        self.variables = {
            "dnn_model_integrity": claripy.BVS("dnn_model_integrity", 8),  # Model integrity status
            "dnn_adversarial_attack_flag": claripy.BVS(
                "dnn_adversarial_attack_flag", 8
            ),  # Adversarial attack detection
            "dnn_bias_flag": claripy.BVS("dnn_bias_flag", 8),  # Bias detection in the model
        }

    parameter_types = {
        "known_source": str,
        "known_weight": str,
        "is_trusted": bool,
        "object_tracking_accuracy": float,
        "false_positive_rate": float,
    }


# =================== Algorithmic Abstraction (Cyber) ===================


class DNNTrackingAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__ + (
        "known_source",
        "known_weight",
        "adversarial_defense",
        "tracking_latency",
        "bounding_box_integrity",
        "adversarial_noise_sensitivity",
        "backdoor_flag",
        "variables",
    )

    def __init__(
        self,
        known_source=None,
        known_weight=None,
        adversarial_defense=True,
        tracking_latency=30,
        bounding_box_integrity=0.98,
        adversarial_noise_sensitivity=0.1,
        **kwargs,
    ):
        """
        :param known_source: Verified source of the DNN model.
        :param known_weight: Verified weights used in the DNN.
        :param adversarial_defense: Boolean indicating if the model has adversarial defense.
        :param tracking_latency: Inference time per frame in milliseconds.
        :param bounding_box_integrity: Consistency of bounding box predictions across frames (0 to 1).
        :param adversarial_noise_sensitivity: How easily tracking is disrupted by noise (0 to 1).
        """
        super().__init__(**kwargs)
        self.known_source = known_source
        self.known_weight = known_weight
        self.adversarial_defense = adversarial_defense
        self.tracking_latency = tracking_latency
        self.bounding_box_integrity = bounding_box_integrity
        self.adversarial_noise_sensitivity = adversarial_noise_sensitivity

        # Security-related symbolic variables
        self.variables = {
            "dnn_confidence_score": claripy.BVS("dnn_confidence_score", 32),  # Model prediction confidence
            "dnn_training_data_integrity": claripy.BVS("dnn_training_data_integrity", 8),  # Data integrity flag
            "dnn_inference_latency": claripy.BVS("dnn_inference_latency", 32),  # Latency in inference
            "dnn_adversarial_robustness": claripy.BVS(
                "dnn_adversarial_robustness", 8
            ),  # Robustness against adversarial attacks
            "backdoor_flag": claripy.BVS("dnn_backdoor_flag", 8),  # Flags possible backdoor insertion in the model
        }

    parameter_types = {
        "known_source": str,
        "known_weight": str,
        "adversarial_defense": bool,
        "tracking_latency": int,
        "bounding_box_integrity": float,
        "adversarial_noise_sensitivity": float,
    }


# =================== Full DNN Tracking Model Abstraction (Cyber) ===================


class DNNTracking(CyberComponentBase):
    __slots__ = ("ABSTRACTIONS", "known_source", "known_weight", "adversarial_defense", "tracking_latency", "variables")

    def __init__(self, known_source=None, known_weight=None, adversarial_defense=True, tracking_latency=30, **kwargs):
        """
        :param known_source: Verified model source.
        :param known_weight: Verified model weights.
        :param adversarial_defense: Boolean indicating if the model has adversarial defense enabled.
        :param tracking_latency: Inference time per frame in milliseconds.
        """
        super().__init__(**kwargs)

        self.known_source = known_source
        self.known_weight = known_weight
        self.adversarial_defense = adversarial_defense
        self.tracking_latency = tracking_latency

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: DNNTrackingHigh(
                known_source=known_source, known_weight=known_weight, is_trusted=True
            ),
            CyberAbstractionLevel.ALGORITHMIC: DNNTrackingAlgorithmic(
                known_source=known_source,
                known_weight=known_weight,
                adversarial_defense=adversarial_defense,
                tracking_latency=tracking_latency,
            ),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }

    parameter_types = {
        "known_source": str,
        "known_weight": str,
        "adversarial_defense": bool,
        "tracking_latency": int,
    }
