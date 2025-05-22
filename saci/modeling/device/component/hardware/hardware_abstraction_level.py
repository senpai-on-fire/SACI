from enum import IntEnum


class HardwareAbstractionLevel(IntEnum):
    HIGH = 0
    TECHNOLOGY = 1
    PACKAGE = 2
    CIRCUIT = 3
    UNKNOWN = 5


HARDWARE_ABSTRACTION_LEVELS = [
    HardwareAbstractionLevel.HIGH,
    HardwareAbstractionLevel.TECHNOLOGY,
    HardwareAbstractionLevel.PACKAGE,
    HardwareAbstractionLevel.CIRCUIT,
]
