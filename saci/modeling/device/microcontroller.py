from .component import HardwarePackage


###### Parameters Examples ######

# Example of Chip vendor: "ARM"
# Example of Chip series: "Cortex"
# Example of Chip name: "M4"


class MicroController(HardwarePackage):
    # TODO -- Consider adding more hardware features later

    parameter_types = {
        "chip_name": str,
        "chip_series": str,
        "chip_vendor": str,
        "trustzone_enabled": bool,
        "mpu_enabled": bool,
        "base_clk_freq": int,
    }


###### Parameters Meaning ######

# Clock: Clock signals for synchronization -- should be identical to the Micro-controller clock signals.
# Trigger: External bit trigger (should be from the Micro-controller) that servers as a trigger event for the voltage
# glitching.
# Offset: Number of clock cycles to count once the trigger bit is asserted to actually start the voltage glitching
# fault.
# Width: Number of clock cycles as the duration of the voltage glitching fault.


class VoltageGlitcher(HardwarePackage):
    # TODO -- Consider adding how the voltage glitcher circuit is connected to the micro-controller

    parameter_types = {
        "glitch_type": str,
        "glitch_objective": str,
        "clock": int,
        "trigger": int,
        "offset": int,
        "width": int,
    }
