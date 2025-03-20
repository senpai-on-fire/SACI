from collections.abc import Hashable
from dataclasses import dataclass
from typing_extensions import Generic, TypeVar

from saci.modeling.communication.base_comm import BaseCommunication
from saci.modeling.device import Device
from saci.modeling.vulnerability import VulnerabilityEffect, BaseVulnerability


CID = TypeVar("CID", bound=Hashable)


class AnnotationVulnerability(BaseVulnerability, Generic[CID]):
    """The device-specific, user-specified component vulnerability derived from an Annotation."""

    def __init__(self, device: Device[CID], comp_id: CID, effect: VulnerabilityEffect):
        super().__init__(
            component=device.components[comp_id],
            _input=BaseCommunication(),
            output=BaseCommunication(),
        )
        self.associated_device = device
        self.effect = effect

    def exists(self, device: Device[CID]) -> bool:
        # TODO: how should we check this?
        # if device != self.associated_device:
        #     raise ValueError("AnnotationVulnerabilities can only be applied to their corresponding device")
        return True

    def effects(self, device: Device[CID]) -> list[VulnerabilityEffect]:
        _ = device
        return [self.effect]


@dataclass(frozen=True)
class Annotation(Generic[CID]):
    """A user-specified annotation on a device describing where a vulnerability lies and its impact.

    Attributes:
        attack_surface: The CID of the affected component within the device.
        effect: The VulnerabilityEffect describing the consequences of this vulnerability.
        underlying_vulnerability: Optionally, a BaseVulnerability that identified this vulnerability as a possible
                                  annotation. It should match on the specified attack_surface component.
        attack_model: Optionally, a string describing how to actually exploit this vulnerability. Eventually this will
                      contain more semantic information than just a generic string, but not for now.
    """

    attack_surface: CID
    effect: VulnerabilityEffect
    underlying_vulnerability: BaseVulnerability | None
    attack_model: str | None

    def validate_against(self, device: Device[CID]) -> bool:
        """Check to make sure this annotation actually makes sense for a given device."""
        if self.attack_surface not in device.components:
            return False
        if self.underlying_vulnerability is not None and not self.underlying_vulnerability.exists(device):
            return False
        # TODO: check that the vulnerability effects, in particular, some components within the attack surface?
        return True

    def into_vulnerability(self, device: Device[CID]) -> AnnotationVulnerability:
        """The derived BaseVulnerability from this annotation, to be used for CPV identification."""
        return AnnotationVulnerability(device, self.attack_surface, self.effect)
