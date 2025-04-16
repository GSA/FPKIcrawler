from __future__ import annotations

import base64
import json
import logging
import os
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, List, Optional, OrderedDict, TYPE_CHECKING

import requests
from asn1crypto import cms, pem, x509

if TYPE_CHECKING:
    from .certificate_path import CertificatePath

logger = logging.getLogger("py_crawler.gsa_cert")


@dataclass
class XiaResult:
    url: str
    status: str
    certs: List["GsaCertificate"]


class GsaCertificate:
    class Status(StrEnum):
        VALID = "Certificate Valid and Chains to Common"
        INVALID = "Certificate Invalid"
        REVOKED = "Certificate Revoked"
        REVOCATION_CHECK_FAILED = "Revocation Check Failed"
        NO_PATH = "Certificate Valid, but no Path to Common"
        UNCHECKED = "unchecked"
        OTHER = "Status set to other because we didn't handle an error condition well"

    cert: x509.Certificate
    cert_dict: OrderedDict[str, Any]
    issuer: str
    subject: str
    status: Status
    pathbuilder_result: dict[str, str]
    sia_results: List[XiaResult]
    aia_results: List[XiaResult]
    path_to_anchor: CertificatePath

    def get_status(self, proposed_path: CertificatePath) -> Status:
        script_directory = Path(os.path.dirname(os.path.abspath(__file__)))
        logger.debug("Checking Certificate Status")
        # If the certificate is expired or not yet valid, don't bother checking anything else
        if (
            "validity" in self.cert_dict.keys()
            and self.cert_dict["validity"]["not_before"] > datetime.now(tz=timezone.utc)
            and self.cert_dict["validity"]["not_after"] < datetime.now(tz=timezone.utc)
        ):
            self.status = self.Status.INVALID
            self.pathbuilder_result["result"] = "false"
            self.pathbuilder_result["details"] = "certificate expired or not yet valid"
        else:
            # If the certificate is valid from a time perspective, run pathbuilder
            logger.debug("Certificate within validity period, running pathbuilder")

            # Create arg list for pathbuilder
            pathbuilder_args = [
                "java",
                "-jar",
                str(script_directory / "data" / "pathbuilder-1.2.jar"),
                "--noshift",
                "--output",
                "short",
                "--base64",
                base64.b64encode(self.cert.dump()),
            ]

            # Get the p7c from the path
            if len(proposed_path.p7c) > 0:
                logger.debug("Intermediate Certs passed to get_status for %s:", self)

                pathbuilder_args.extend(
                    [
                        "--bundle-base64",
                        base64.b64encode(proposed_path.p7c),
                    ]
                )
            logger.debug("Pathbuilder command arguments %s", pathbuilder_args)

            pathbuilder_process = None

            try:
                pathbuilder_process = subprocess.run(
                    pathbuilder_args,
                    check=True,
                    timeout=10,
                    capture_output=True,
                    encoding="utf8",
                )
            except subprocess.CalledProcessError as cpe:
                error = f"Calling pathbuilder failed: {cpe.stderr}"
                logger.critical(error)
                self.status = self.Status.REVOCATION_CHECK_FAILED
                self.pathbuilder_result["result"] = "false"
                self.pathbuilder_result["details"] = error
            except subprocess.TimeoutExpired:
                error = "Pathbuilder timed out"
                logger.critical(error)
                self.status = self.Status.REVOCATION_CHECK_FAILED
                self.pathbuilder_result["result"] = "false"
                self.pathbuilder_result["details"] = error

            if pathbuilder_process is not None:
                logger.debug(pathbuilder_process.stdout.rstrip())
                pathbuilder_status = json.loads(pathbuilder_process.stdout)
                self.pathbuilder_result.update(pathbuilder_status)

                if pathbuilder_status["result"] == "true":
                    # If the path verification was successful, save the path
                    self.path_to_anchor = proposed_path
                    self.status = self.Status.VALID
                elif pathbuilder_status["result"] == "false":
                    if pathbuilder_status["details"] == "Unable to build Path":
                        self.status = self.Status.NO_PATH
                    elif (
                        pathbuilder_status["details"]
                        == "End Entity Cert expired or not valid"
                    ):
                        self.status = self.Status.INVALID
                    else:
                        self.status = self.Status.OTHER

        return self.status

    def __init__(self, input_bytes: bytes = b"") -> None:
        # Initialize instance variables YOU MUST DO THIS OR THE VALUES ARE SHARED BY ALL INSTANCES OF THE CLASS!
        self.sia_results = []
        self.aia_results = []
        self.pathbuilder_result = {}

        if len(input_bytes) > 0:
            cert_bytes: Optional[bytes]  # This is to prevent a linting error
            cert: x509.Certificate
            if pem.detect(input_bytes):
                # Ignoring type for next assignment due to obscure API behavior
                _, _, cert_bytes = pem.unarmor(input_bytes)  # type: ignore
                cert = x509.Certificate.load(cert_bytes)

                if cert.native is not None:
                    self.cert = cert
                    self.cert_dict = cert.native["tbs_certificate"]
            else:
                cert = x509.Certificate.load(input_bytes)
                if cert.native is not None:
                    self.cert = cert
                    self.cert_dict = cert.native["tbs_certificate"]
        else:
            raise Exception("Must provide a bytestream.")

        subject = ""
        for rdn in reversed(self.cert_dict["subject"].keys()):
            if type(self.cert_dict["subject"][rdn]) == str:
                subject += rdn + ":" + self.cert_dict["subject"][rdn] + ","
            elif type(self.cert_dict["subject"][rdn]) == list:
                for element in reversed(self.cert_dict["subject"][rdn]):
                    subject += rdn + ":" + element + ","
        # strip the final comma from the string before returning
        self.subject = subject[:-1]

        issuer = ""
        for rdn in reversed(self.cert_dict["issuer"].keys()):
            if type(self.cert_dict["issuer"][rdn]) == str:
                issuer += rdn + ":" + self.cert_dict["issuer"][rdn] + ","
            elif type(self.cert_dict["issuer"][rdn]) == list:
                for element in reversed(self.cert_dict["issuer"][rdn]):
                    issuer += rdn + ":" + element + ","
        # strip the final comma from the string before returning
        self.issuer = issuer[:-1]

        logger.info("Got certificate %s", self)

        self.status = self.Status.UNCHECKED

    @property
    def path_identifier(self) -> str:
        # Certificates that need to know whether this cert is above them in the path
        # need to match their issuer name and akid to the subject and skid in this cert.
        # this identifier is <subject>:<skid>, which facilitates that discovery
        path_identifier = self.subject + ":"
        if self.cert.key_identifier is not None:
            # Note this shouldn't happen in Fed PKI
            path_identifier += "".join(
                "{:02x}".format(byte) for byte in self.cert.key_identifier
            )
        return path_identifier

    @property
    def path_parent_identifier(self) -> str:
        # To identify which cert should be a parent concatinate the issuer name and
        # the authority key id, which should match the subject and skid of the node above it
        # in the path
        path_parent_identifier = self.issuer + ":"
        if self.cert.authority_key_identifier is not None:
            # Note this shouldn't happen in Fed PKI
            path_parent_identifier += "".join(
                "{:02x}".format(byte) for byte in self.cert.authority_key_identifier
            )
        return path_parent_identifier

    @property
    def identifier(self) -> str:
        identifier = str(self.issuer) + ":"
        identifier += str(self.cert_dict["serial_number"])
        return identifier

    def __str__(self) -> str:
        return (
            self.issuer
            + " -> "
            + self.subject
            + ":"
            + str(self.cert_dict["serial_number"])
        )

    def is_trust_anchor(self) -> bool:
        # Some certs in the graph are trust anchors without any path.
        # If we identify one of these, we can stop processing
        # This function returns true if the cert is an anchor
        if (
            self.cert.subject == self.cert.issuer
            and self.cert.ca
            and self.cert.authority_information_access_value == None
        ):
            return True

        return False

    def get_info_access_result_http(self, url: str) -> XiaResult:
        status: str = "UNKNOWN"
        found_certs: List["GsaCertificate"] = []
        logger.debug("Fetching P7C from %s", url)
        info_access_response: requests.models.Response = requests.get(url)
        if info_access_response:
            logger.info("Got P7C file from %s", url)
        else:
            logger.warning("Unable to get P7C file from %s", url)
            status = "ACCESS ERROR"

        # Process SIA data to extract certs
        if len(info_access_response.content) > 0:
            p7c: Optional[cms.ContentInfo] = None
            try:
                p7c = cms.ContentInfo.load(info_access_response.content)
            except ValueError:
                status = "Invalid P7C"

            status = "OK"

            if (
                p7c != None
                and type(p7c) == cms.ContentInfo
                and p7c["content"] is not None
            ):
                for cert in p7c["content"]["certificates"]:
                    found_certs.append(GsaCertificate(input_bytes=cert.dump()))
        else:
            status = "Zero-byte P7C"

        return XiaResult(url=url, status=status, certs=found_certs)

    def get_sia_certs(self) -> List["GsaCertificate"]:
        sia_certs: list[GsaCertificate] = []

        # If we haven't looked at the SIA, do it now.
        if len(self.sia_results) == 0:
            sia_values = [
                extension["extn_value"]
                for extension in self.cert_dict["extensions"]
                if extension["extn_id"] == "subject_information_access"
            ]

            for sia_value in sia_values:
                for value_dict in sia_value:
                    if (
                        "access_method" in value_dict.keys()
                        and value_dict["access_method"] == "ca_repository"
                        and "access_location" in value_dict.keys()
                    ):
                        sia_url = value_dict["access_location"]
                        logger.debug("Found SIA URL %s", sia_url)
                        self.sia_results.append(self.get_info_access_url(sia_url))

        # Get the certs from the SIAs
        for result in self.sia_results:
            sia_certs.extend(result.certs)

        logger.debug("Returning %s certs from SIA", len(sia_certs))
        return sia_certs

    def get_aia_certs(self) -> List["GsaCertificate"]:
        aia_certs: list[GsaCertificate] = []

        # Populate the aia_results attributes based on any discovered AIA URLs
        if len(self.aia_results) == 0:
            aia_values = [
                extension["extn_value"]
                for extension in self.cert_dict["extensions"]
                if extension["extn_id"] == "authority_information_access"
            ]

            for aia_value in aia_values:
                for value_dict in aia_value:
                    if (
                        "access_method" in value_dict.keys()
                        and value_dict["access_method"] == "ca_issuers"
                        and "access_location" in value_dict.keys()
                    ):
                        aia_url = value_dict["access_location"]
                        logger.debug("Found AIA URL %s", aia_url)
                        self.aia_results.append(self.get_info_access_url(aia_url))

        # Get the certs for all processed AIAs
        for result in self.aia_results:
            aia_certs.extend(result.certs)

        logger.debug("Found %s certs in AIA fields", str(len(aia_certs)))
        return aia_certs

    def get_info_access_url(self, info_access_url: str) -> XiaResult:
        if info_access_url.startswith("http://"):
            logger.debug("Found HTTP URL %s in %s", info_access_url, self)
            return self.get_info_access_result_http(info_access_url)

        elif info_access_url.startswith("ldap://"):
            logger.debug("Skipping LDAP URL %s in %s", info_access_url, self)
            return XiaResult(info_access_url, "Unsupported schema", [])
        else:
            logger.debug("Unknown URI scheme in URL %s", info_access_url)
            return XiaResult(info_access_url, "Unsupported schema", [])
