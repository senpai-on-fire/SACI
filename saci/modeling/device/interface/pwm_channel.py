import logging

import claripy

from saci.modeling.device.component import (
    CyberAbstractionLevel,
    CyberComponentAlgorithmic,
    CyberComponentBase,
    CyberComponentBinary,
    CyberComponentHigh,
    CyberComponentSourceCode,
    HardwareAbstractionLevel,
    HardwareCircuit,
    HardwareComponentBase,
    HardwareHigh,
)

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction (Cyber) ===================


class PWMChannelCyberHigh(CyberComponentHigh):
    __slots__ = CyberComponentBase.__slots__ + (
        "protection",
        "integrity_check",
        "variables",
    )

    def __init__(self, protection=None, integrity_check=True, **kwargs):
        """
        :param protection: Security protection applied to the PWM signal.
        :param integrity_check: Whether the PWM signal is checked for integrity.
        """
        super().__init__(**kwargs)
        self.protection = protection or "None"
        self.integrity_check = integrity_check

        # Symbolic execution for PWM integrity and failure detection
        self.variables = {
            "pwm_signal_integrity": claripy.BVS("pwm_signal_integrity", 8),  # Integrity status
            "pwm_jitter": claripy.BVS("pwm_jitter", 32),  # Jitter measurement
            "pwm_anomaly_flag": claripy.BVS("pwm_anomaly_flag", 8),  # Anomaly detection flag
        }

    parameter_types = {
        "protection": str,
        "integrity_check": bool,
    }


# =================== Algorithmic Abstraction (Cyber) ===================


class PWMChannelAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__ + (
        "modulation_type",
        "timing_accuracy",
        "variables",
    )

    def __init__(self, modulation_type="PWM", timing_accuracy=99.9, **kwargs):
        """
        :param modulation_type: Type of modulation used (e.g., PWM, PPM).
        :param timing_accuracy: Signal timing accuracy percentage (0-100%).
        """
        super().__init__(**kwargs)
        self.modulation_type = modulation_type
        self.timing_accuracy = timing_accuracy

        # Symbolic execution variables for PWM signal behavior
        self.variables = {
            "pwm_duty_cycle_variation": claripy.BVS("pwm_duty_cycle_variation", 32),
            "pwm_signal_latency": claripy.BVS("pwm_signal_latency", 32),
            "pwm_frequency_drift": claripy.BVS("pwm_frequency_drift", 32),
        }

    parameter_types = {
        "modulation_type": str,
        "timing_accuracy": float,
    }


# =================== High-Level Abstraction (Hardware) ===================


class PWMChannelHardwareHigh(HardwareHigh):
    __state_slots__ = HardwareHigh.__state_slots__ + ("voltage_level", "duty_cycle", "frequency")
    __slots__ = HardwareHigh.__slots__ + ("voltage_level", "duty_cycle", "frequency")

    def __init__(self, voltage_level=5.0, duty_cycle=50.0, frequency=50.0, **kwargs):
        """
        :param voltage_level: Voltage level of the PWM signal.
        :param duty_cycle: Duty cycle of the PWM signal in percentage.
        :param frequency: Frequency of the PWM signal in Hz.
        """
        super().__init__(**kwargs)
        self.voltage_level = voltage_level
        self.duty_cycle = duty_cycle
        self.frequency = frequency

    parameter_types = {
        "voltage_level": float,
        "duty_cycle": float,
        "frequency": float,
    }


# =================== Circuit-Level Abstraction (Hardware) ===================


class PWMChannelHardwareCircuit(HardwareCircuit):
    __slots__ = HardwareCircuit.__slots__ + ("signal_impedance", "signal_noise", "harmonic_distortion")

    def __init__(self, signal_impedance=50, signal_noise=5, harmonic_distortion=2, **kwargs):
        """
        :param signal_impedance: Impedance of the PWM signal in ohms.
        :param signal_noise: Noise level in dB.
        :param harmonic_distortion: Harmonic distortion percentage.
        """
        super().__init__(**kwargs)
        self.signal_impedance = signal_impedance
        self.signal_noise = signal_noise
        self.harmonic_distortion = harmonic_distortion

    parameter_types = {
        "signal_impedance": float,
        "signal_noise": float,
        "harmonic_distortion": float,
    }


# =================== Full PWM Channel Abstraction (Hardware) ===================


class PWMChannelHardware(HardwareComponentBase):
    __slots__ = ("ABSTRACTIONS",)

    def __init__(self, voltage_level=5.0, duty_cycle=50.0, frequency=50.0, **kwargs):
        super().__init__(**kwargs)

        high_abstraction = PWMChannelHardwareHigh(
            voltage_level=voltage_level, duty_cycle=duty_cycle, frequency=frequency
        )
        circuit_abstraction = PWMChannelHardwareCircuit()

        self.ABSTRACTIONS = {
            HardwareAbstractionLevel.HIGH: high_abstraction,
            HardwareAbstractionLevel.CIRCUIT: circuit_abstraction,
        }


# =================== Full PWM Channel Model ===================


class PWMChannel(CyberComponentBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: PWMChannelCyberHigh(**kwargs),
            CyberAbstractionLevel.ALGORITHMIC: PWMChannelAlgorithmic(**kwargs),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
            HardwareAbstractionLevel.HIGH: PWMChannelHardwareHigh(**kwargs),
            HardwareAbstractionLevel.CIRCUIT: PWMChannelHardwareCircuit(**kwargs),
        }

    parameter_types = {
        "protection": str,
        "integrity_check": bool,
        "modulation_type": str,
        "timing_accuracy": float,
        "voltage_level": float,
        "duty_cycle": float,
        "frequency": float,
        "signal_impedance": float,
        "signal_noise": float,
        "harmonic_distortion": float,
    }
