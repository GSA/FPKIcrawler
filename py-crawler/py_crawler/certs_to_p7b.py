from __future__ import annotations

from typing import List, TYPE_CHECKING

from asn1crypto import cms, pem

if TYPE_CHECKING:
    from .gsa_certificate import GsaCertificate


class P7C:
    certs: List[GsaCertificate]

    def __init__(self, intermediate_certs: List[GsaCertificate]) -> None:
        self.certs = intermediate_certs

    def get_bytes(self) -> bytes:
        p7c_bytes: bytes
        p7c_certs = cms.CertificateSet()

        for gsaCert in self.certs:
            p7c_certs.append(cms.CertificateChoices({"certificate": gsaCert.cert}))

        p7c_input = cms.SignedData(
            {
                "version": "v1",
                "digest_algorithms": [],
                "encap_content_info": {
                    "content_type": "data",
                    "content": b"",
                },
                "certificates": p7c_certs,
                "signer_infos": [],
            }
        )

        p7c_obj = cms.ContentInfo(
            {
                "content_type": "signed_data",
                "content": p7c_input,
            }
        )

        p7c_bytes = p7c_obj.dump()

        return p7c_bytes

    def get_p7b(self) -> bytes:
        return pem.armor(type_name="PKCS7", der_bytes=self.get_bytes(), headers=None)
