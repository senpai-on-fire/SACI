import json
import logging

from saci_db import vulns as vulns

from ..atoms import Atoms
from ..modeling import device as device
from .cpv import CPV
from .device import ComponentBase, Device

l = logging.getLogger(__name__)


class CPVHypothesis(CPV):
    def __init__(self, fd):
        self.hypothesis = json.load(fd)
        if "Required Components" in self.hypothesis:
            self.required_components = self._convert_to_components(self.hypothesis["Required Components"])
        else:
            self.required_components = self._convert_to_components(self._check_atoms(self.hypothesis["Kinetic Effect"]))
        self.entry_component, self.exit_component = self._extract(self.required_components)
        self.vulnerabilities = self._convert_to_vulns(self.hypothesis["Vulnerabilities"])

    def _check_atoms(self, effect):
        finder = list(filter(lambda x: x["Kinetic Effect"] == effect, Atoms))
        if len(finder) > 0:
            return finder[0]["Required Components"]
        return None

    def _convert_to_components(self, components_text):
        return list(map(lambda t: getattr(device, t)(), components_text))

    def _convert_to_vulns(self, vulns_text):
        return list(map(lambda t: getattr(vulns, t)(), vulns_text))

    def _extract(self, components):
        if len(components) == 1:
            return components[0], components[0]
        else:
            # TODO: in theory, the order can be obtained through the current CPS.
            # Now we just assume that the first is head and the last is exit.
            l.warn("We decide the entrance and exit component dictatingly")
            return components[0], components[-1]

    def _match(self, component, required):
        ll = list(required.ABSTRACTIONS.values()) + [required]
        if not any(map(lambda req_c: type(component) is type(req_c), ll)):
            return False
        return True

    def is_possible_path(self, path: list[ComponentBase]):
        for required in self.required_components:
            if not any(map(lambda p: self._match(p, required), path)):
                return False
        return True

    def vulnerable(self, device: Device):
        if self.vulnerabilities is not None:
            return super().vulnerable(device)
        else:
            return True
