from __future__ import annotations

import networkx

from .certificate_graph import CertificateGraph


class GraphNetwork:
    graph: networkx.MultiDiGraph

    def __init__(self, cert_graph: CertificateGraph) -> None:
        self.graph = networkx.MultiDiGraph()

        self.graph.add_nodes_from(cert_graph.nodes)

        self.graph.add_edges_from(
            [(edge.issuer, edge.subject) for edge in cert_graph.edges.values()]
        )
