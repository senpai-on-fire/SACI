from .component import HardwarePackage, HardwareComponentBase, HardwareAbstractionLevel

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





