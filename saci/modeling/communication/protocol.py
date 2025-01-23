from .auth_comm import AuthenticatedCommunication
from .unauth_comm import UnauthenticatedCommunication

class GPSProtocol(UnauthenticatedCommunication):
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