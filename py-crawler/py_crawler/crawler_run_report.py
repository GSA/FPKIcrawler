from __future__ import annotations

import json
import logging
import datetime

from .certificate_graph import CertificateGraph
from .gsa_certificate import GsaCertificate

logger = logging.getLogger("py_crawler.crawler_run_report")


class CrawlerRunReport:
    def __init__(self, run_graph: CertificateGraph) -> None:
        self.report = {}
        self.report["anchor"] = run_graph.anchor.issuer
        self.report["changes"] = {}
        # new_certs has every cert that is less than two weeks old
        self.report["changes"]["new_certs"] = [
            identifier
            for identifier in run_graph.edges
            if datetime.datetime.now(tz=datetime.timezone.utc)
            - run_graph.edges[identifier].cert.not_valid_before
            < datetime.timedelta(weeks=2)
        ]
        self.report["issuers"] = [node for node in run_graph.sorted_nodes]
        self.report["valid-certs"] = [
            self.cert_report(cert=cert) for cert in run_graph.sorted_edges.values()
        ]
        self.report["bad-certs"] = [
            self.cert_report(cert=cert)
            for cert in run_graph.sorted_no_path_certs.values()
        ]
        self.report["found-paths"] = [
            path.description for path in run_graph.paths.values()
        ]

    def cert_report(self, cert: GsaCertificate):
        report_entry: dict[str, str | list[str] | dict[str, str | list[str]]] = {}
        report_entry["subject"] = cert.subject
        report_entry["issuer"] = cert.issuer
        report_entry["serial-number"] = str(cert.cert.serial_number)
        if cert.cert.authority_key_identifier is not None:
            report_entry["akid"] = " ".join(
                "{:02x}".format(byte)
                for byte in bytes(cert.cert.authority_key_identifier)
            )
        if cert.cert.key_identifier is not None:
            report_entry["skid"] = " ".join(
                "{:02x}".format(byte) for byte in bytes(cert.cert.key_identifier)
            )
        report_entry["status"] = cert.status
        report_entry["pathbuilder-result"] = cert.pathbuilder_result
        if cert.status == cert.Status.VALID:
            if len(cert.path_to_anchor.certs) > 0:
                report_entry["path-to-common"] = [
                    path_cert.subject for path_cert in cert.path_to_anchor.certs
                ]

            report_entry["sia-entries"] = {}
            for result in cert.sia_results:
                report_entry["sia-entries"][result.url] = [
                    sia_cert.subject for sia_cert in result.certs
                ]

            report_entry["aia-entries"] = {}
            for result in cert.aia_results:
                report_entry["aia-entries"][result.url] = [
                    aia_cert.issuer for aia_cert in result.certs
                ]

        elif cert.status == cert.Status.INVALID:
            report_entry["parent_path_identifier"] = cert.path_parent_identifier
            report_entry["validity-dates"] = {
                "not-before": str(cert.cert.not_valid_before),
                "not-after": str(cert.cert.not_valid_after),
            }

        return report_entry

    def to_json(self) -> str:
        return json.dumps(self.report, indent=4)
