from saci.modeling.device.component import (
    CyberComponentAlgorithmic,
    CyberComponentBase,
    CyberComponentBinary,
    CyberComponentHigh,
    CyberComponentSourceCode,
)
from saci.modeling.device.component.cyber.cyber_abstraction_level import CyberAbstractionLevel


class AttitudeControlLogicHigh(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__ + ("control_algorithm", "stability_tuned")

    def __init__(self, control_algorithm=None, stability_tuned=False, **kwargs):
        """
        :param control_algorithm: High-level description of the control algorithm (e.g., PID, LQR, or Adaptive Control).
        :param stability_tuned: Indicates whether the control parameters have been tuned for stability.
        """
        super().__init__(**kwargs)
        self.control_algorithm = control_algorithm
        self.stability_tuned = stability_tuned


class AttitudeControlLogicAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__ + ("control_algorithm", "stability_tuned", "gain_parameters")

    def __init__(self, control_algorithm=None, stability_tuned=False, gain_parameters=None, **kwargs):
        """
        :param control_algorithm: Detailed description of the control algorithm (e.g., PID gains or state-space
        matrices).
        :param stability_tuned: Indicates whether the control parameters have been tuned for stability.
        :param gain_parameters: Algorithmic representation of the control parameters (e.g., PID gains or matrices).
        """
        super().__init__(**kwargs)
        self.control_algorithm = control_algorithm
        self.stability_tuned = stability_tuned
        self.gain_parameters = gain_parameters or {
            "proportional_gain": 0.0,
            "integral_gain": 0.0,
            "derivative_gain": 0.0,
        }


class AttitudeControlLogic(CyberComponentBase):
    __slots__ = ("ABSTRACTIONS", "control_algorithm", "stability_tuned", "gain_parameters")

    def __init__(self, control_algorithm=None, stability_tuned=False, gain_parameters=None, **kwargs):
        """
        :param control_algorithm: Description of the control algorithm used (e.g., PID, LQR, etc.).
        :param stability_tuned: Whether the control logic is tuned for stability.
        :param gain_parameters: Control parameters for the algorithm (e.g., PID gains or state-space matrices).
        """
        super().__init__(**kwargs)

        self.control_algorithm = control_algorithm
        self.stability_tuned = stability_tuned
        self.gain_parameters = gain_parameters or {
            "proportional_gain": 0.0,
            "integral_gain": 0.0,
            "derivative_gain": 0.0,
        }

        # Define abstractions for different cyber abstraction levels
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: AttitudeControlLogicHigh(
                control_algorithm=control_algorithm,
                stability_tuned=stability_tuned,
            ),
            CyberAbstractionLevel.ALGORITHMIC: AttitudeControlLogicAlgorithmic(
                control_algorithm=control_algorithm,
                stability_tuned=stability_tuned,
                gain_parameters=self.gain_parameters,
            ),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }
