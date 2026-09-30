from __future__ import annotations

import hashlib
from pathlib import Path
from typing import List, TYPE_CHECKING
from asn1crypto import cms, pem

if TYPE_CHECKING:
    from .gsa_certificate import GsaCertificate


def load_excluded_thumbprints() -> set[str]:
    # Resolves to the repo root where exclude_thumbprints.txt lives
    root_dir = Path(__file__).resolve().parents[1]
    exclude_file = root_dir / "exclude_thumbprints.txt"

    if not exclude_file.exists():
        return set()

    with open(exclude_file, "r", encoding="utf-8") as f:
        return {
            line.strip().replace(":", "").replace(" ", "").lower()
            for line in f
            if line.strip() and not line.startswith("#")
        }


class P7C:
    certs: List[GsaCertificate]

    def __init__(self, intermediate_certs: List[GsaCertificate]) -> None:
        self.certs = intermediate_certs

    def get_bytes(self) -> bytes:
        p7c_bytes: bytes
        p7c_certs = cms.CertificateSet()

        excluded_thumbprints = load_excluded_thumbprints()

        for gsaCert in self.certs:
            cert_der = gsaCert.cert.dump()
            
            # Calculate both SHA-1 and SHA-256 thumbprints
            sha1_thumbprint = hashlib.sha1(cert_der).hexdigest().lower()
            sha256_thumbprint = hashlib.sha256(cert_der).hexdigest().lower()

            # Skip if either thumbprint is in the exclusion set
            if sha1_thumbprint in excluded_thumbprints or sha256_thumbprint in excluded_thumbprints:
                continue

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
