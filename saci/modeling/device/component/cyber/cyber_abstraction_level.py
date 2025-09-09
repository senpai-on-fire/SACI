from enum import IntEnum


class CyberAbstractionLevel(IntEnum):
    HIGH = 0
    ALGORITHMIC = 1
    SOURCE = 2
    BINARY = 3
    FUNCTION = 4
    UNKNOWN = 5


CYBER_ABSTRACTION_LEVELS = [
    CyberAbstractionLevel.HIGH,
    CyberAbstractionLevel.ALGORITHMIC,
    CyberAbstractionLevel.SOURCE,
    CyberAbstractionLevel.BINARY,
]
