from .auth_comm import AuthenticatedCommunication
from .unauth_comm import UnauthenticatedCommunication


class SMBusProtocol(UnauthenticatedCommunication):
    def __init__(self, src=None, dst=None, data=None):
        super().__init__(src=src, dst=dst, data=data)


class JTAGProtocol(UnauthenticatedCommunication):
    def __init__(self, src=None, dst=None, data=None):
        super().__init__(src=src, dst=dst, data=data)


class SWDProtocol(UnauthenticatedCommunication):
    def __init__(self, src=None, dst=None, data=None):
        super().__init__(src=src, dst=dst, data=data)


class GPSProtocol(UnauthenticatedCommunication):
    def __init__(self, src=None, dst=None, data=None):
        super().__init__(src=src, dst=dst, data=data)


class GNSSProtocol(UnauthenticatedCommunication):
    def __init__(self, src=None, dst=None, data=None):
        super().__init__(src=src, dst=dst, data=data)


class GLONASSProtocol(UnauthenticatedCommunication):
    def __init__(self, src=None, dst=None, data=None):
        super().__init__(src=src, dst=dst, data=data)


class GalileoProtocol(UnauthenticatedCommunication):
    def __init__(self, src=None, dst=None, data=None):
        super().__init__(src=src, dst=dst, data=data)


class BeiDouProtocol(UnauthenticatedCommunication):
    def __init__(self, src=None, dst=None, data=None):
        super().__init__(src=src, dst=dst, data=data)


class UARTProtocol(UnauthenticatedCommunication):
    def __init__(self, src=None, dst=None, data=None):
        super().__init__(src=src, dst=dst, data=data)


class SPIProtocol(UnauthenticatedCommunication):
    def __init__(self, src=None, dst=None, data=None):
        super().__init__(src=src, dst=dst, data=data)


class SSHProtocol(AuthenticatedCommunication):
    def __init__(self, src=None, dst=None, data=None):
        super().__init__(src=src, dst=dst, data=data)


class HTTPProtocol(UnauthenticatedCommunication):
    def __init__(self, src=None, dst=None, data=None):
        super().__init__(src=src, dst=dst, data=data)


class HTTPSProtocol(AuthenticatedCommunication):
    def __init__(self, src=None, dst=None, data=None):
        super().__init__(src=src, dst=dst, data=data)


class I2CProtocol(UnauthenticatedCommunication):
    def __init__(self, src=None, dst=None, data=None):
        super().__init__(src=src, dst=dst, data=data)


class USBProtocol(UnauthenticatedCommunication):
    def __init__(self, src=None, dst=None, data=None):
        super().__init__(src=src, dst=dst, data=data)


class BlueToothProtocol(AuthenticatedCommunication):
    def __init__(self, src=None, dst=None, data=None):
        super().__init__(src=src, dst=dst, data=data)


class MavlinkProtocol(AuthenticatedCommunication):
    def __init__(self, src=None, dst=None, data=None):
        super().__init__(src=src, dst=dst, data=data)


class SikProtocol(AuthenticatedCommunication):
    def __init__(self, src=None, dst=None, data=None):
        super().__init__(src=src, dst=dst, data=data)


class TelemetryProtocol(UnauthenticatedCommunication):
    def __init__(self, src=None, dst=None, data=None):
        super().__init__(src=src, dst=dst, data=data)


class NMEA0183Protocol(UnauthenticatedCommunication):
    def __init__(self, src=None, dst=None, data=None):
        super().__init__(src=src, dst=dst, data=data)


class WifiBProtocol(UnauthenticatedCommunication):
    # 802.11b
    pass


class WifiGProtocol(UnauthenticatedCommunication):
    # 802.11g
    pass


class WifiNProtocol(UnauthenticatedCommunication):
    # 802.11n
    pass


class CANProtocol(UnauthenticatedCommunication):
    def __init__(self, src=None, dst=None, data=None):
        super().__init__(src=src, dst=dst, data=data)
