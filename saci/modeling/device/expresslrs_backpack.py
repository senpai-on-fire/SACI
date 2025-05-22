from .component import (
    CyberComponentAlgorithmic,
    CyberComponentBase,
    CyberComponentBinary,
    CyberComponentHigh,
    CyberComponentSourceCode,
)
from .component.cyber.cyber_abstraction_level import CyberAbstractionLevel


class ExpressLRSBackpack(CyberComponentBase):
    __slots__ = ("ABSTRACTIONS", "protocol", "mode")

    def __init__(self, protocol="CRSF", mode="RECEIVER_TO_FC", **kwargs):
        """Initialize ExpressLRSBackpack.

        :param protocol: Communication protocol used by Backpack (e.g., CRSF).
        :param mode: Direction or mode of communication (e.g., "RECEIVER_TO_FC",
            "FC_TO_ACCESSORY").
        """
        super().__init__(**kwargs)

        self.protocol = protocol
        self.mode = mode

        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: ExpressLRSBackpackHigh(
                protocol=self.protocol, mode=self.mode
            ),
            CyberAbstractionLevel.ALGORITHMIC: ExpressLRSBackpackAlgorithmic(
                protocol=self.protocol, mode=self.mode
            ),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }


class ExpressLRSBackpackHigh(CyberComponentHigh):
    __slots__ = ("protocol", "mode", "connected_device", "data_rate")

    def __init__(
        self,
        protocol="CRSF",
        mode="RECEIVER_TO_FC",
        connected_device=None,
        data_rate="Low",
        **kwargs,
    ):
        """Initialize ExpressLRSBackpackHigh.

        :param protocol: Protocol used for communication (e.g., CRSF).
        :param mode: Communication direction.
        :param connected_device: Device connected to the backpack (e.g., flight
            controller).
        :param data_rate: Relative throughput of the Backpack link ("Low",
            "Medium", "High").
        """
        super().__init__(**kwargs)
        self.protocol = protocol
        self.mode = mode
        self.connected_device = connected_device
        self.data_rate = data_rate


class ExpressLRSBackpackAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = ("protocol", "mode", "connected_device", "data_buffer")

    def __init__(
        self,
        protocol="CRSF",
        mode="RECEIVER_TO_FC",
        connected_device=None,
        data_buffer=None,
        **kwargs,
    ):
        """Initialize ExpressLRSBackpackAlgorithmic.

        :param protocol: Protocol used for communication (e.g., CRSF).
        :param mode: Direction of communication.
        :param connected_device: Connected component (e.g., controller).
        :param data_buffer: Stores exchanged messages.
        """
        super().__init__(**kwargs)
        self.protocol = protocol
        self.mode = mode
        self.connected_device = connected_device
        self.data_buffer = data_buffer or []

    def send_data(self, message):
        """Send a message via Backpack.

        :param message: Data to send to the connected device.
        """
        print(f"[Backpack] Sending: {message}")
        self.data_buffer.append(("sent", message))

    def receive_data(self, message):
        """Receive a message via Backpack.

        :param message: Data received from the connected device.
        """
        print(f"[Backpack] Received: {message}")
        self.data_buffer.append(("received", message))

    def attach_device(self, device_name):
        """Attach a new device to the Backpack.

        :param device_name: Identifier of the device (e.g.,
            'ArduPilotController').
        """
        self.connected_device = device_name
        print(f"Device '{device_name}' connected to ExpressLRSBackpack.")