import logging
import os
from datetime import datetime
from importlib import resources
from pathlib import Path

from . import data
from .certificate_graph import CertificateGraph
from .certs_to_p7b import P7C
from .graph_gexf import GraphGexf
from .gsa_certificate import GsaCertificate
from .crawler_run_report import CrawlerRunReport


def main():
    P7B_FILE_NAME = "CACertificatesValidatingToFederalCommonPolicyG2.p7b"
    GEXF_FILE_NAME = "fpki-certs.gexf"

    # Identify and create output directories
    if "OUTPUT_DIR" in os.environ:
        output_path = Path(os.environ["OUTPUT_DIR"])
    else:
        output_path = Path.cwd().parent

    log_path = Path(output_path, "logs")
    report_path = Path(output_path, "reports")

    if not output_path.exists():
        Path.mkdir(output_path, parents=True)

    if not log_path.exists():
        Path.mkdir(log_path)

    if not report_path.exists():
        Path.mkdir(report_path)

    logger = logging.getLogger("py_crawler")
    logger.setLevel(logging.DEBUG)
    file_logger = logging.FileHandler(
        Path(log_path, "debug_log-" + str(datetime.now().isoformat()) + ".log")
    )
    file_logger.setLevel(logging.DEBUG)
    logger.addHandler(file_logger)
    logger.debug("Starting Run and logging %s messages", file_logger.level)

    # Start with Common Policy Root
    common_file = resources.files(data).joinpath("fcpcag2.crt")

    with common_file.open(mode="rb") as common_file:
        common_bytes = common_file.read()

    anchor = GsaCertificate(input_bytes=common_bytes)

    # Create a graph
    common_graph = CertificateGraph(anchor=anchor)
    common_graph.build_graph()

    # First lets create a report of the certs discovered
    logger.info("Creating report for this crawler run.")
    run_report = CrawlerRunReport(common_graph)
    report_filename = "crawler-" + str(datetime.now().isoformat()) + ".json"
    with open(Path(report_path, report_filename), "w") as report:
        report.write(run_report.to_json())

    logger.info("Writing latest report to output directory")
    latest_report_filename = "crawler-lastrun.json"
    with open(Path(output_path, latest_report_filename), "w") as latest_report:
        latest_report.write(run_report.to_json())

    # Next, produce a P7C
    logger.info("Creating P7B file")
    common_p7b = P7C(list(common_graph.edges.values()))

    with open(Path(output_path, P7B_FILE_NAME), "wb") as common_p7b_file:
        common_p7b_file.write(common_p7b.get_p7b())

    # build the gexf output
    logger.info("building gexf")
    common_gexf = GraphGexf(cert_graph=common_graph)
    graph_xml = common_gexf.tostring()
    if graph_xml is not None:
        with open(Path(output_path, GEXF_FILE_NAME), "w") as graph_file:
            # Write file
            graph_file.write(graph_xml)


if __name__ == "__main__":
    main()
