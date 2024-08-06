from .component import HardwarePackage, HardwareComponentBase, HardwareAbstractionLevel


###### Parameters Examples ######

# Example of Chip vendor: "ARM"
# Example of Chip series: "Cortex"
# Example of Chip name: "M4"

class MicroController(HardwarePackage):

    __slots__ = HardwareComponentBase.__slots__ + ("chip_vendor", "chip_series", "chip_subname")

    def __init__(self, chip_vendor, chip_series, chip_name, trustzone_enabled, mpu_enabled, base_clk_freq, **kwargs):
        super().__init__(**kwargs)

        self.chip_name = chip_name
        self.chip_series = chip_series
        self.chip_vendor = chip_vendor

        self.trustzone_enabled = trustzone_enabled
        self.mpu_enabled = mpu_enabled

        self.base_clk_freq = base_clk_freq

        #TODO -- Consider adding more hardware features later


###### Parameters Meaning ######

# Clock: Clock signals for synchronization -- should be identical to the Micro-controller clock signals.
# Trigger: External bit trigger (should be from the Micro-controller) that servers as a trigger event for the voltage glitching.
# Offset: Number of clock cycles to count once the trigger bit is asserted to actually start the voltage glitching fault.
# Width: Number of clock cycles as the duration of the voltage glitching fault.


class VoltageGlitcher(HardwarePackage):

    __slots__ = HardwareComponentBase.__slots__ + ("glitch_type", "glitch_objective")

    def __init__(self, clock, trigger, offset, width, **kwargs):
        super().__init__(**kwargs)

        self.clock = clock
        self.trigger = trigger
        self.offset = offset
        self.width = width

        #TODO -- Consider adding how the voltage glitcher circuit is connected to the micro-controller

