import sys
from enum import Enum

if sys.version_info >= (3, 11):
    from enum import StrEnum
else:
    class StrEnum(str, Enum):
        pass


class Capability(StrEnum):
    ACCELEROMETER = "accelerometer"
    GYROSCOPE = "gyroscope"
    ICMP = "icmp"
    MAVLINK = "mavlink"
    STEERING = "steering"
    WEB_SERVER = "web_server"
    WIFI = "wifi"
