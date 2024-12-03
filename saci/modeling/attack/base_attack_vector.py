
from typing import List, Type, Optional, Dict, Tuple
from saci.modeling.device.component import CyberComponentBase
from .base_attack_signal import BaseAttackSignal

class BaseAttackVector:
    def __init__(self, 
                 name: str,
                 src: str,
                 signal:BaseAttackSignal, 
                 dst:CyberComponentBase, 
                 required_access_level: str,
                 configuration: tuple[str, ...] = (),
                 options: tuple[str, ...] = (),
    ):
        
        self.name = name
        self.src = src
        self.signal = signal
        self.dst = dst
        self.required_access_level = required_access_level
        self.configuration = configuration
        self.options = options

    def get_configuration(self, name):
        pass

    def set_configuration(self, name, value):
        pass

    def get_option(self, name):
        pass

    def set_option(self, name, value):
        pass
