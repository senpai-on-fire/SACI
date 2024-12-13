
from .base_attack_signal import BaseAttackSignal

class BaseAttackVector:
    def __init__(self, 
                 name: str,
                 signal:BaseAttackSignal, 
                 required_access_level: str,
                 configuration: dict[str, str] = {},
                 options: tuple[str, ...] = (),
    ):
        
        self.name = name
        self.signal = signal
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
