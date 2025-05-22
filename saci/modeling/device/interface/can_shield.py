import logging
import claripy

from saci.modeling.device.component import (
    HardwareComponentBase,
    HardwareAbstractionLevel,
    HardwareHigh,
    HardwareCircuit,
    HardwareTechnology,
    HardwarePackage,
)

_l = logging.getLogger(__name__)

# =================== High-Level Abstraction ===================


class CANShieldHigh(HardwareHigh):
    __slots__ = HardwareHigh.__slots__ + (
        "shield_type",
        "supports_fd",
        "voltage_tolerance",
        "variables",
    )

    def __init__(
        self,
        shield_type="SN65HVD230",
        supports_fd=False,
        voltage_tolerance=5.0,
        **kwargs,
    ):
        """
        :param shield_type: Model/type of the CAN shield (e.g., SN65HVD230).
        :param supports_fd: Whether CAN-FD is supported.
        :param voltage_tolerance: Max operating voltage.
        """
        super().__init__(**kwargs)
        self.shield_type = shield_type
        self.supports_fd = supports_fd
        self.voltage_tolerance = voltage_tolerance

        self.variables = {
            "can_shield_model": claripy.BVS("can_shield_model", 32),
            "can_fd_support": claripy.BVS("can_fd_support", 1),
            "can_voltage_tolerance": claripy.BVS("can_voltage_tolerance", 32),
        }


# =================== Circuit-Level Abstraction ===================


class CANShieldCircuit(HardwareCircuit):
    __slots__ = HardwareCircuit.__slots__ + (
        "esd_protection",
        "line_protection",
        "bus_isolation",
        "variables",
    )

    def __init__(
        self,
        esd_protection=True,
        line_protection=True,
        bus_isolation=True,
        **kwargs,
    ):
        """
        :param esd_protection: Whether ESD protection is provided.
        :param line_protection: Whether signal lines are protected.
        :param bus_isolation: Whether electrical isolation is included.
        """
        super().__init__(**kwargs)
        self.esd_protection = esd_protection
        self.line_protection = line_protection
        self.bus_isolation = bus_isolation

        self.variables = {
            "can_esd_protection": claripy.BVS("can_esd_protection", 1),
            "can_line_protection": claripy.BVS("can_line_protection", 1),
            "can_bus_isolation": claripy.BVS("can_bus_isolation", 1),
        }


# =================== Full CAN Shield Component ===================


class CANShield(HardwareComponentBase):
    __slots__ = ("ABSTRACTIONS",)

    def __init__(
        self,
        shield_type="SN65HVD230",
        supports_fd=False,
        voltage_tolerance=5.0,
        **kwargs,
    ):
        super().__init__(**kwargs)

        high_abstraction = CANShieldHigh(
            shield_type=shield_type,
            supports_fd=supports_fd,
            voltage_tolerance=voltage_tolerance,
        )
        circuit_abstraction = CANShieldCircuit()

        self.ABSTRACTIONS = {
            HardwareAbstractionLevel.HIGH: high_abstraction,
            HardwareAbstractionLevel.CIRCUIT: circuit_abstraction,
        }


# =================== Hardware Metadata ===================


class CANShieldPackage(HardwarePackage):
    KNOWN_SHIELD_MODELS = [
        "SN65HVD230",
        "MCP2551",
        "TJA1050",
        "MAX3051",
        "TCAN332",
    ]

    def __init__(self, shield_model, manufacturer, **kwargs):
        """
        :param shield_model: Shield/controller chip model.
        :param manufacturer: Vendor of the CAN shield.
        """
        super().__init__(chip_name=shield_model, chip_vendor=manufacturer, **kwargs)
        if shield_model not in self.KNOWN_SHIELD_MODELS:
            _l.warning(
                f"Unknown CAN shield model: {shield_model}. "
                "Please add it to CANShieldPackage.KNOWN_SHIELD_MODELS.",
            )


class CANShieldTechnology(HardwareTechnology):
    KNOWN_TECHNOLOGIES = [
        "Isolated CAN",
        "Non-Isolated CAN",
        "CAN-FD",
        "High-Speed CAN",
    ]

    def __init__(self, technology, **kwargs):
        """
        :param technology: CAN shield implementation type.
        """
        super().__init__(technology=technology, **kwargs)
        if technology not in self.KNOWN_TECHNOLOGIES:
            _l.warning(
                f"Unknown CAN shield technology: {technology}. "
                "Please add it to CANShieldTechnology.KNOWN_TECHNOLOGIES.",
            )
