from __future__ import annotations

import math
import logging

from datetime import date
from typing import Optional
from xml.etree import ElementTree
from xml.dom import minidom

from .certificate_graph import CertificateGraph

logger = logging.getLogger("py_crawler.graph_gexf")


class GraphGexf:
    # The graph used to create the gexf data
    cert_graph: CertificateGraph

    # a list of dicts representing nodes
    # nodes[subject] = shortest path to anchor - used to calculate geometry
    nodes: dict[str, int] = {}

    # An object to store the GEXF contents
    xml_graph: ElementTree.ElementTree

    # To layout the graph using the current library, we will need to identify
    # the number of concentric rings and the number of elements per ring.
    # We define a where the key is the ring id and the value is the number of elements.
    ring_geometry: dict[int, int] = {}

    # Useful constants
    NODE_SIZE = "10.0"
    NODE_COLOR_R = "153"
    NODE_COLOR_G = "0"
    NODE_COLOR_B = "153"

    EDGE_COLOR_R = "153"
    EDGE_COLOR_G = "0"
    EDGE_COLOR_B = "153"

    XMLNS_DICT = {
        "xmlns": "http://gexf.net/1.3",
        "xmlns:viz": "http://gexf.net/1.3/viz",
        "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
        "xsi:schemaLocation": "http://gexf.net/1.3 http://gexf.net/1.3/gexf.xsd",
        "version": "1.3",
    }

    GEXF_TYPE = "directed"
    GEXF_MODE = "static"

    def get_node_location(
        self, ring_id: int, ring_index: int, ring_size: int
    ) -> tuple[int, int]:
        x_location = y_location = 0

        logger.debug(
            "Calling get_node_location with ring_id %s, ring_index %s, and ring_size %s",
            ring_id,
            ring_index,
            ring_size,
        )
        if ring_index == 0 and ring_size == 0:
            pass
        else:
            radius = 100 * ring_id
            radians = ((2 * math.pi) / ring_size) * ring_index

            x_location = math.ceil(radius * math.cos(radians))
            y_location = math.ceil(radius * math.sin(radians))

            logger.debug(
                "Node Location information - radius: %s, radians: %s, x_location: %s, y_location: %s",
                radius,
                radians,
                x_location,
                y_location,
            )

        return (x_location, y_location)

    def write_node(
        self,
        node_name: str,
        ring: int,
        ring_index: int,
    ) -> ElementTree.Element:
        # The label is the CN, which is everything after the first colon, but before the first comma
        node_label = (node_name.split(sep=":")[1]).split(",")[0]

        node_element = ElementTree.Element(
            "node", attrib={"id": node_name, "label": node_label}
        )
        node_element.append(
            ElementTree.Element("size", attrib={"value": self.NODE_SIZE})
        )
        node_element.append(
            ElementTree.Element(
                "viz:color",
                attrib={
                    "r": self.NODE_COLOR_R,
                    "g": self.NODE_COLOR_G,
                    "b": self.NODE_COLOR_B,
                },
            )
        )

        (x_location, y_location) = self.get_node_location(
            ring_id=ring,
            ring_index=ring_index,
            ring_size=self.ring_geometry[ring],
        )

        node_geometry_dict = {
            "x": str(x_location) + ".0",
            "y": str(y_location) + ".0",
            "z": "0.0",
        }

        node_element.append(
            ElementTree.Element("viz:position", attrib=node_geometry_dict)
        )

        return node_element

    def __init__(self, cert_graph: CertificateGraph) -> None:
        self.cert_graph = cert_graph

        node_ids = self.cert_graph.sorted_nodes

        # Get all the certs that are not self-signed or self-issued (these confuse gexf).
        edge_certs = [
            cert
            for cert in cert_graph.sorted_edges.values()
            if cert.subject != cert.issuer
        ]

        # Build the node list
        # Calculate the shortest path from the node to the anchor,
        # if there is more than one cert with the node as the subject
        for node in node_ids:
            edges_to_node = [
                len(cert.path_to_anchor.certs)
                for cert in edge_certs
                if cert.subject == node
            ]

            if len(edges_to_node) > 0:
                # In case there are multiple paths from a node to the anchor, choose
                # the shortest. If there is only one, min() returns it
                self.nodes[node] = min(edges_to_node)

        # Manually set the anchor to the center of the graph
        self.nodes[cert_graph.anchor.issuer] = 0

        # Calculate ring geometry, the number of rings (with anchor at the center)
        # and the number of points in each ring

        # Start with the center
        self.ring_geometry[0] = 1

        # Add 1 more point to the corresponding ring. If the key doesn't exist, create
        # it with a value of 1
        for circle in self.nodes.values():
            try:
                logger.debug("Adding 1 to ring[%s]", circle)
                self.ring_geometry[circle] += 1
            except KeyError:
                logger.debug("Initializing ring[%s] with value 1", circle)
                self.ring_geometry[circle] = 1

        # Root
        root_element = ElementTree.Element("gexf", attrib=self.XMLNS_DICT)

        # Metadata
        meta_element = ElementTree.Element(
            "meta",
            attrib={"lastmodifieddate": date.isoformat(date.today())},
        )

        # Creator
        creator_element = ElementTree.Element("creator")
        creator_element.text = "py-crawler"
        meta_element.append(creator_element)

        # Description
        description_element = ElementTree.Element("description")
        description_element.text = (
            f"Created by Py-Crawler on {date.today().isoformat()}"
        )
        meta_element.append(description_element)

        # Attach completed metadata to root
        root_element.append(meta_element)

        # Create the Graph element under the root
        graph_element = ElementTree.Element(
            "graph",
            attrib={"defaultedgetype": self.GEXF_TYPE, "mode": self.GEXF_MODE},
        )

        # Create the nodes
        nodes_element = ElementTree.Element("nodes")

        # Initialize a dict to track the geometry for the node rings
        ring_tracker = {x: 0 for x in self.ring_geometry.keys()}

        # Step through the nodes and create an XML element for each one
        for node_name, ring in self.nodes.items():
            nodes_element.append(
                self.write_node(
                    node_name=node_name, ring=ring, ring_index=ring_tracker[ring]
                )
            )
            ring_tracker[ring] += 1

        # Add the nodes to the graph
        graph_element.append(nodes_element)

        # Create the edges
        edges_element = ElementTree.Element("edges")
        edges_dict: dict[str, dict[str, str]] = {}

        for edge_cert in edge_certs:
            edge_label = (edge_cert.subject.split(sep=":")[1]).split(",")[0]

            edges_dict[edge_label] = {
                "id": edge_cert.subject,
                "source": edge_cert.issuer,
                "target": edge_cert.subject,
                "label": edge_label,
                "weight": "1.0",
            }

        for label in edges_dict:
            edge_element = ElementTree.SubElement(
                edges_element,
                "edge",
                attrib=edges_dict[label],
            )

            edge_element.append(
                ElementTree.Element(
                    "viz:color",
                    attrib={
                        "r": self.NODE_COLOR_R,
                        "g": self.NODE_COLOR_G,
                        "b": self.NODE_COLOR_B,
                    },
                )
            )

        # Add the edges to the graph
        graph_element.append(edges_element)

        # Add the graph to the root
        root_element.append(graph_element)

        self.xml_graph = ElementTree.ElementTree(root_element)

    def tostring(self) -> Optional[str]:
        return minidom.parseString(
            ElementTree.tostring(self.xml_graph.getroot(), encoding="unicode")
        ).toprettyxml(indent="    ")
