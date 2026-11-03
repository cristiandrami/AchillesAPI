
#!/usr/bin/env python3
"""
AchillesAPI JSON Graph Exporter

Converts AchillesAPI relationship graph JSON into a
Gephi-compatible GEXF file with pastel nodes and visible edges.
"""

import argparse
import json
import xml.etree.ElementTree as ET
from pathlib import Path

import networkx as nx


GEXF_NS = "http://www.gexf.net/1.2draft"
VIZ_NS = "http://www.gexf.net/1.2draft/viz"

ET.register_namespace("", GEXF_NS)
ET.register_namespace("viz", VIZ_NS)


# Pastel node colors (RGB)
COLORS = {
    "endpoint": (174, 198, 232),
    "resource": (180, 218, 190),
    "identifier": (245, 211, 160),
    "security_scheme": (232, 180, 180),
    "request_property": (210, 190, 230),
    "response_property": (190, 220, 220),
    "schema": (225, 215, 190),
    "property": (215, 215, 215),
}

DEFAULT_COLOR = (210, 210, 210)

# Node sizes
NODE_SIZES = {
    "endpoint": 26,
    "resource": 19,
    "identifier": 17,
    "security_scheme": 19,
    "request_property": 15,
    "response_property": 15,
    "schema": 18,
    "property": 14,
}


def node_label(node: dict) -> str:
    """Generate readable labels for Gephi nodes."""

    node_type = node.get("type", "unknown")

    if node_type == "endpoint":
        return f'{node.get("method", "")} {node.get("path", "")}'

    if node_type == "resource":
        return node.get("path", "Resource")

    if node_type == "identifier":
        return f'ID: {node.get("name", "")}'

    if node_type == "security_scheme":
        return f'AUTH: {node.get("name", "")}'

    if node_type in {
        "property",
        "request_property",
        "response_property",
    }:
        return f'{node_type}: {node.get("name", "")}'

    return node.get("name", node.get("id", "Unknown"))


def json_value(value):
    """Convert JSON values to GraphML/GEXF-compatible attributes."""

    if value is None:
        return None

    if isinstance(value, (str, int, float, bool)):
        return value

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
    )


def add_node_visuals(element, node_type):
    """Add Gephi-compatible node visualization attributes."""

    r, g, b = COLORS.get(node_type, DEFAULT_COLOR)

    ET.SubElement(
        element,
        f"{{{VIZ_NS}}}color",
        {
            "r": str(r),
            "g": str(g),
            "b": str(b),
            "a": "1.0",
        },
    )

    size = NODE_SIZES.get(node_type, 15)

    ET.SubElement(
        element,
        f"{{{VIZ_NS}}}size",
        {"value": str(size)},
    )


def add_edge_visuals(element):
    """Add subtle but visible edge styling."""

    ET.SubElement(
        element,
        f"{{{VIZ_NS}}}color",
        {
            "r": "155",
            "g": "165",
            "b": "178",
            "a": "0.9",
        },
    )

    ET.SubElement(
        element,
        f"{{{VIZ_NS}}}thickness",
        {"value": "1.8"},
    )


def main():

    parser = argparse.ArgumentParser(
        description="Export AchillesAPI graph to colored GEXF for Gephi"
    )

    parser.add_argument(
        "input",
        type=Path,
        help="Input AchillesAPI JSON graph",
    )

    parser.add_argument(
        "output",
        type=Path,
        help="Output GEXF file",
    )

    args = parser.parse_args()

    # Load AchillesAPI JSON
    payload = json.loads(
        args.input.read_text(encoding="utf-8")
    )

    graph = nx.MultiDiGraph(
        name="AchillesAPI Relationship Graph"
    )

    node_types = {}

    # Build nodes
    for node in payload.get("nodes", []):

        node_id = str(node["id"])
        node_type = node.get("type", "unknown")

        node_types[node_id] = node_type

        attrs = {
            key: converted
            for key, value in node.items()
            if key != "id"
            and (converted := json_value(value)) is not None
        }

        attrs["label"] = node_label(node)

        graph.add_node(
            node_id,
            **attrs,
        )

    # Build directed edges
    for index, edge in enumerate(payload.get("edges", [])):

        source = str(edge["from"])
        target = str(edge["to"])

        attrs = {
            key: converted
            for key, value in edge.items()
            if key not in {"from", "to"}
            and (converted := json_value(value)) is not None
        }

        attrs["label"] = edge.get(
            "relation",
            "RELATED",
        )

        graph.add_edge(
            source,
            target,
            key=str(index),
            **attrs,
        )

    # Ensure output directory exists
    args.output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Export initial GEXF
    nx.write_gexf(
        graph,
        args.output,
    )

    # Parse GEXF to inject Gephi visualization attributes
    tree = ET.parse(args.output)
    root = tree.getroot()

    nodes_element = root.find(
        f".//{{{GEXF_NS}}}nodes"
    )

    edges_element = root.find(
        f".//{{{GEXF_NS}}}edges"
    )

    if nodes_element is None:
        raise RuntimeError("GEXF nodes section not found")

    if edges_element is None:
        raise RuntimeError("GEXF edges section not found")

    # Apply node colors and sizes
    for element in nodes_element.findall(
        f"{{{GEXF_NS}}}node"
    ):

        node_id = element.get("id")
        node_type = node_types.get(
            node_id,
            "unknown",
        )

        add_node_visuals(
            element,
            node_type,
        )

    # Apply edge colors and thickness
    for element in edges_element.findall(
        f"{{{GEXF_NS}}}edge"
    ):

        add_edge_visuals(element)

    # Save final GEXF
    tree.write(
        args.output,
        encoding="utf-8",
        xml_declaration=True,
    )

    print("\nAchillesAPI graph exported successfully")
    print("----------------------------------------")
    print(f"Output: {args.output}")
    print(f"Nodes:  {graph.number_of_nodes()}")
    print(f"Edges:  {graph.number_of_edges()}")
    print("Format: GEXF")
    print("Directed graph: YES")
    print("Pastel node colors: YES")
    print("Visible edge styling: YES")
    print("----------------------------------------\n")


if __name__ == "__main__":
    main()
