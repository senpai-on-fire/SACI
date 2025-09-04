from enum import StrEnum


class Capability(StrEnum):
    ACCELEROMETER = "accelerometer"
    GYROSCOPE = "gyroscope"
    ICMP = "icmp"
    MAVLINK = "mavlink"
    STEERING = "steering"
    WEB_SERVER = "web_server"
    WIFI = "wifi"
