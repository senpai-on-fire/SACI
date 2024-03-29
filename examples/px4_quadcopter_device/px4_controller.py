from saci.modeling.device import ControllerHigh


class PX4ControllerHigh(ControllerHigh):
    def __init__(self):
        super().__init__(name="px4_controller_high")


