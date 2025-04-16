from __future__ import annotations

from typing import TYPE_CHECKING
from dataclasses import dataclass, field

from .certs_to_p7b import P7C

if TYPE_CHECKING:
    from .gsa_certificate import GsaCertificate


@dataclass
class CertificatePath:
    # This represents a CertifiatePath - designed to speed up processing by caching potential paths

    # end_identifier is the path_identifer of the last element in the path - creating a longer path just requires us to copy this
    # and add the new "end"
    end_identifier: str = field(init=False)
    # a list of the subject IDs in the path, so that we can pretty print the path
    description: list[str] = field(init=False)
    # A list of the certs in the path
    certs: list[GsaCertificate]
    # A representation of the path in p7c der format
    p7c: bytes = field(init=False)

    def __post_init__(self):
        if len(self.certs) > 0:
            self.description = [cert.subject for cert in self.certs]
            self.end_identifier = self.certs[-1].subject
            self.p7c = P7C(intermediate_certs=list(self.certs)).get_bytes()
        else:
            self.p7c = bytes()
