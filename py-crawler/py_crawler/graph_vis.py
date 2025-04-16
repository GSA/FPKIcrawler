from __future__ import annotations

import json

from dataclasses import dataclass
from typing import Union

from .certificate_graph import CertificateGraph


# Generate VIS graph
class GraphVis:
    # Using a list of dicts because we want this to be easily serialized to JSON
    nodes = list[dict[str, Union[int, str]]]
    edges = list[dict[str, Union[int, str]]]

    def __init__(self, cert_graph: CertificateGraph) -> None:
        # Initialize the nodes and edges list
        self.nodes = self.edges = []

        # use a dict to track the number of times we see an edge or node, so we can assign a weight/value
        nodevalue: dict[str, int] = {}
        edgeweight: dict[tuple[str, str], int] = {}

        # Loop through the edges to calculate all the weights and sizes
        for edge in cert_graph.edges.values():
            graph_edge = {}

            edge_id = (edge.issuer, edge.subject)
            if edge_id not in edgeweight:
                # First time we've seen this issuer, subject tuple
                self.edges.append({"from": edge.issuer, "to": edge.subject})
                edgeweight[edge_id] = 1
            else:
                # Increase the weight of this edge by 1
                edgeweight[edge_id] += 1

            if edge.issuer not in nodevalue:
                nodevalue[edge.issuer] = 1
            else:
                nodevalue[edge.issuer] += 1

        # Assign the weights to the edges
        for edge in self.edges:
            try:
                edge["weight"] = edgeweight[(edge["from"], edge["to"])]
            except KeyError as ke:
                edge["weight"] = 1

        for node in cert_graph.nodes:
            # Extract the lowest RDN from the DN
            node_label = (node.split(sep=":")[1]).split(",")[0]
            self.nodes.append({"id": node, "value": nodevalue[node], "label": node_label})
            pass

        def to_json(self) -> str:
            graph_json = {}
            graph_json["nodes"] = self.nodes
            graph_json["edges"] = self.edges
            return json.dumps(graph_json, indent=4)
