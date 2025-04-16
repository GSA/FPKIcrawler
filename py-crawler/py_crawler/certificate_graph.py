from __future__ import annotations

import logging

from .certificate_path import CertificatePath
from .gsa_certificate import GsaCertificate

logger = logging.getLogger("py_crawler.cert_graph")


class CertificateGraph:
    # The root and trust anchor
    anchor: GsaCertificate
    # The set of Issuer DNs
    nodes: set[str]
    # All of the certificates in the graph
    edges: dict[str, GsaCertificate]
    # Pre-cached paths to make processing faster
    paths: dict[str, CertificatePath]
    # A list of certificates discovered but for which the path could not be built
    # (e.g. invalid, revoked, etc.)
    no_path_certs: dict[str, GsaCertificate]

    def __init__(self, anchor: GsaCertificate) -> None:
        # set the root to the trust anchor
        self.anchor = anchor

        # Initalize the empty data structures
        self.nodes = set()
        self.edges = {}
        self.no_path_certs = {}
        self.paths = {}

        # We add a special status for the root, since the "get_status" function doesn't make sense for
        # the trust anchor
        logger.debug("Trusting Anchor %s", self.anchor)
        self.anchor.status = GsaCertificate.Status.VALID
        self.anchor.pathbuilder_result = {"result": "true", "details": "Trust Anchor"}

        # Create a "pseudo-path" for the root. The trust anchor is never actually in the path, but
        # the get_path function is seeded with an empty path for the Anchor
        logger.debug(
            "Adding empty path for anchor with key %s", self.anchor.path_identifier
        )
        self.paths[
            self.anchor.path_identifier
        ] = self.anchor.path_to_anchor = CertificatePath(certs=[])

    @property
    def sorted_nodes(self) -> list[str]:
        return sorted(self.nodes)

    @property
    def sorted_edges(self) -> dict[str, GsaCertificate]:
        return {key: self.edges[key] for key in sorted(self.edges.keys())}

    @property
    def sorted_no_path_certs(self) -> dict[str, GsaCertificate]:
        return {
            key: self.no_path_certs[key] for key in sorted(self.no_path_certs.keys())
        }

    def get_path(self, leaf_cert: GsaCertificate) -> CertificatePath:
        # Provide a list of intermediate certs between the leaf and the root to facilitate
        # path validation
        logger.debug("Getting intermediates for %s", leaf_cert.subject)

        # See if we have already identified the path of the certificate's issuer
        try:
            logger.debug("Getting path ending at %s", leaf_cert.path_parent_identifier)
            return self.paths[leaf_cert.path_parent_identifier]

        except KeyError:
            # We don't have the parent's path

            # Log a warning, and add that info to the path processor result
            # field of the cert
            logger.warning("Found Cert in SIA without Parent: %s", leaf_cert.identifier)
            leaf_cert.pathbuilder_result[
                "WARNING"
            ] = "Certificate is present in SIA of a CA that is not its issuer"
            raise Exception("Path from %s to root not found.", leaf_cert)

    def add_valid_cert_to_graph_and_get_Xia_certs(
        self, cert: GsaCertificate
    ) -> list[GsaCertificate]:
        certs_to_process: list[GsaCertificate] = []
        logger.debug("Adding %s to nodes", cert.issuer)
        self.nodes.add(cert.issuer)
        logger.debug("Adding %s to nodes", cert.subject)
        self.nodes.add(cert.subject)
        logger.debug("Adding cert %s to edges", cert)
        self.edges[cert.identifier] = cert
        logger.debug("Adding path designated %s", cert.path_identifier)
        self.paths[cert.path_identifier] = CertificatePath(
            cert.path_to_anchor.certs + [cert]
        )

        logger.debug(
            "Adding SIA and AIA certificates from %s to certs_to_process.",
            cert,
        )

        # Add any certs in the sia to the list of certs to process
        certs_to_process.extend(cert.get_sia_certs())

        # Add any certs in the aia to the list of certs to process
        certs_to_process.extend(cert.get_aia_certs())

        return certs_to_process

    def build_graph(self):
        # List of unprocessed certs - we will add to this as we discover new certs
        certs_to_process: list[GsaCertificate] = [self.anchor]

        # List of certs that have been definitively processed, success or failure
        processed_certs: dict[str, GsaCertificate] = {}

        # List of certs that we attempted to process, but couldn't find the path for.
        # We will try a second pass when we've sorted everything else:
        purgatory_certs: list[GsaCertificate] = []

        logger.debug("Beginning processing of cert graph at %s", self.anchor.identifier)

        # certs_to_process is a list of certs to be reviewed. When the cert is processed,
        # it is moved to the processed_certs list. When new certs are discovered, they
        # are added to the list. When the certs_to_process list is empty (i.e. all
        # certs have been discovered and processed) we exit.
        while len(certs_to_process) > 0:
            # Add the first cert in the list, and remove it from certs_to_process
            cert_to_process = certs_to_process.pop(0)

            # Check to see if we've already processed this cert (May appear in multiple SIA/AIA fields)
            if cert_to_process.identifier in processed_certs.keys():
                # If so, skip it.
                logger.info("#########")
                logger.info("Skipping already processed cert %s", cert_to_process)
                logger.info("#########")

            else:
                # IF not , process it
                logger.info("#########")
                logger.info("Processing certificate %s", cert_to_process)
                logger.info("#########")

                # First, check to see if we have a root cert other than the graph root
                if cert_to_process != self.anchor and cert_to_process.is_trust_anchor():
                    cert_to_process.status = GsaCertificate.Status.NO_PATH
                    cert_to_process.pathbuilder_result[
                        "INFO"
                    ] = "Certificate is a trust anchor, but not the root of the graph"
                    # Create an empty Certificate Path
                    # cert_to_process.path_to_anchor = CertificatePath(certs=[])
                    self.no_path_certs[str(cert_to_process)] = cert_to_process

                # Next see if the certificate status is UNCHECKED
                if cert_to_process.status == GsaCertificate.Status.UNCHECKED:
                    try:
                        # see if we've already got a path to pass to pathbuilder (pathbuilder will only validate)
                        logger.debug(
                            "Looking for cert using path_parent_identifier %s",
                            cert_to_process.path_parent_identifier,
                        )
                        cert_to_process.path_to_anchor = self.get_path(
                            leaf_cert=cert_to_process
                        )
                        # If so, check the status of the cert with pathbuilder
                        cert_to_process.status = cert_to_process.get_status(
                            proposed_path=cert_to_process.path_to_anchor
                        )
                    # If anything goes wrong, send the cert to purgatory for now
                    except Exception:
                        logger.debug(
                            "Path not found. Sending %s to purgatory",
                            cert_to_process,
                        )
                        purgatory_certs.append(cert_to_process)

                logger.debug(
                    "Status of Cert %s is %s",
                    cert_to_process,
                    str(cert_to_process.status),
                )

                # IF we were successful in validating the cert, or we are processing the anchor, add it to the graph
                if cert_to_process.status == GsaCertificate.Status.VALID:
                    logger.debug("Cert %s valid", cert_to_process)

                    certs_to_process.extend(
                        self.add_valid_cert_to_graph_and_get_Xia_certs(
                            cert=cert_to_process
                        )
                    )

                elif cert_to_process.status == GsaCertificate.Status.UNCHECKED:
                    # We should only get here if the we could't find a path.
                    # We have already sent the cert to purgatory, so just log the event and move on
                    logger.debug(
                        "Sent %s to purgatory. Will reprocess in second pass.",
                        cert_to_process,
                    )
                else:
                    # We should only get here if we found a path, but something happened in processing
                    logger.debug(
                        "FAILED - sending %s to failed", cert_to_process.identifier
                    )
                    self.no_path_certs[str(cert_to_process)] = cert_to_process
                    logger.info("Skipping invalid or revoked cert %s", cert_to_process)

                # Add the processed cert to the list of processes certs
                processed_certs[cert_to_process.identifier] = cert_to_process

        # End of while loop

        # When we reach this point, every cert should be in processed_certs or purgatory_certs
        # We will take one more pass at purgatory certs, and send them to heaven or hell
        logger.debug("Processing %s certs in purgatory.", len(purgatory_certs))

        # First, we clear the list or processed certs
        logger.debug(
            "Clearing processed certs list so we can start over with certs in purgatory"
        )
        processed_certs.clear()

        # To be extra sure we get everything, we're going to do one pass to build paths for all the certs in the list
        for cert_to_process in purgatory_certs:
            if cert_to_process.identifier in processed_certs.keys():
                # If so, skip it.
                logger.info("#########")
                logger.info("Skipping already processed cert %s", cert_to_process)
                logger.info("#########")

            else:
                try:
                    logger.debug("Checking for path for %s", cert_to_process)
                    cert_to_process.path_to_anchor = self.get_path(
                        leaf_cert=cert_to_process
                    )
                    cert_to_process.status = cert_to_process.get_status(
                        proposed_path=cert_to_process.path_to_anchor
                    )
                except Exception:
                    logger.debug(
                        "Path not found for %s during first round.",
                        cert_to_process.identifier,
                    )

                if cert_to_process.status == GsaCertificate.Status.VALID:
                    logger.debug("Success at last for %s", cert_to_process.identifier)
                    for cert in self.add_valid_cert_to_graph_and_get_Xia_certs(
                        cert=cert_to_process
                    ):
                        if cert.identifier not in processed_certs:
                            purgatory_certs.append(cert)

                    # Add the processed cert to the list of processes certs
                    processed_certs[cert_to_process.identifier] = cert_to_process

        # Now we'll try again - just in case we found the missing path
        for cert_to_process in purgatory_certs:
            if cert_to_process.identifier in processed_certs.keys():
                # If so, skip it.
                logger.info("#########")
                logger.info("Skipping already processed cert %s", cert_to_process)
                logger.info("#########")

            else:
                try:
                    cert_to_process.path_to_anchor = self.get_path(
                        leaf_cert=cert_to_process
                    )
                    cert_to_process.status = cert_to_process.get_status(
                        proposed_path=cert_to_process.path_to_anchor
                    )
                except Exception:
                    logger.debug(
                        "Path not found for %s during second round. Sending to failed",
                        cert_to_process.identifier,
                    )
                    self.no_path_certs[str(cert_to_process)] = cert_to_process

                if cert_to_process.status == GsaCertificate.Status.VALID:
                    logger.debug("Success at last for %s", cert_to_process.identifier)
                    for cert in self.add_valid_cert_to_graph_and_get_Xia_certs(
                        cert=cert_to_process
                    ):
                        if cert.identifier not in processed_certs:
                            purgatory_certs.append(cert)

                    # Add the processed cert to the list of processes certs
                    processed_certs[cert_to_process.identifier] = cert_to_process

                else:
                    # We get here when we couldn't get the cert to work on the second path
                    logger.debug(
                        "Repeatedly failed to find a path. Sending %s to failed",
                        cert_to_process.identifier,
                    )
                    self.no_path_certs[str(cert_to_process)] = cert_to_process

        logger.info("#########")
        logger.info("End of crawler run")
        logger.info(
            "Discovered %s certs. %s good and %s failed",
            len(self.edges) + len(self.no_path_certs),
            len(self.edges),
            len(self.no_path_certs),
        )
        logger.info("#########")
