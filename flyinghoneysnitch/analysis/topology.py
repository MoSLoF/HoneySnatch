"""Wireless network topology mapping for HoneyView.

Builds and analyzes the topology of discovered wireless networks,
including AP-client relationships, mesh networks, and device groupings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from flyinghoneysnitch.core.models import AccessPoint, Client, ScanSession
from flyinghoneysnitch.utils.logger import get_logger

log = get_logger("topology")


@dataclass
class TopologyNode:
    """A node in the wireless topology graph."""

    identifier: str  # BSSID or MAC
    node_type: str  # "ap" or "client"
    label: str  # SSID, vendor, or MAC
    rssi: int = -100
    encryption: str = ""
    vendor: str = ""
    channel: int = 0
    metadata: dict = field(default_factory=dict)


@dataclass
class TopologyEdge:
    """An edge (connection) between two nodes."""

    source: str  # Source identifier
    target: str  # Target identifier
    edge_type: str  # "associated", "probed", "data"
    weight: int = 1  # Data frame count or connection strength
    metadata: dict = field(default_factory=dict)


@dataclass
class TopologyGraph:
    """Complete topology graph for a scan session."""

    nodes: dict[str, TopologyNode] = field(default_factory=dict)
    edges: list[TopologyEdge] = field(default_factory=list)

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    def get_neighbors(self, identifier: str) -> list[str]:
        """Get all nodes connected to the given node."""
        neighbors = set()
        for edge in self.edges:
            if edge.source == identifier:
                neighbors.add(edge.target)
            elif edge.target == identifier:
                neighbors.add(edge.source)
        return sorted(neighbors)

    def get_ap_clients(self, bssid: str) -> list[str]:
        """Get all clients associated with an AP."""
        clients = []
        for edge in self.edges:
            if edge.source == bssid and edge.edge_type == "associated":
                clients.append(edge.target)
            elif edge.target == bssid and edge.edge_type == "associated":
                clients.append(edge.source)
        return clients

    def to_dict(self) -> dict:
        """Convert to a dictionary for serialization."""
        return {
            "nodes": [
                {
                    "id": n.identifier,
                    "type": n.node_type,
                    "label": n.label,
                    "rssi": n.rssi,
                    "encryption": n.encryption,
                    "vendor": n.vendor,
                    "channel": n.channel,
                    **n.metadata,
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "type": e.edge_type,
                    "weight": e.weight,
                    **e.metadata,
                }
                for e in self.edges
            ],
        }


class TopologyBuilder:
    """Builds wireless network topology from scan session data."""

    def build(self, session: ScanSession) -> TopologyGraph:
        """Build a topology graph from a scan session.

        Args:
            session: The scan session with discovered APs and clients.

        Returns:
            TopologyGraph with nodes and edges.
        """
        graph = TopologyGraph()

        # Add AP nodes
        for ap in session.access_points.values():
            graph.nodes[ap.bssid] = TopologyNode(
                identifier=ap.bssid,
                node_type="ap",
                label=ap.ssid or f"[{ap.bssid}]",
                rssi=ap.rssi,
                encryption=ap.encryption.value,
                vendor=ap.vendor,
                channel=ap.channel,
                metadata={
                    "hidden": ap.hidden,
                    "beacon_count": ap.beacon_count,
                    "data_count": ap.data_count,
                    "wps": ap.wps,
                    "client_count": len(ap.clients),
                },
            )

        # Add client nodes and edges
        for cl in session.clients.values():
            graph.nodes[cl.mac] = TopologyNode(
                identifier=cl.mac,
                node_type="client",
                label=cl.vendor or cl.mac,
                rssi=cl.rssi,
                vendor=cl.vendor,
                metadata={
                    "probe_count": len(cl.probe_requests),
                    "data_count": cl.data_count,
                },
            )

            # Association edge
            if cl.bssid and cl.bssid in graph.nodes:
                graph.edges.append(TopologyEdge(
                    source=cl.bssid,
                    target=cl.mac,
                    edge_type="associated",
                    weight=cl.data_count or 1,
                ))

            # Probe request edges
            for ssid in cl.probe_requests:
                # Find the AP with this SSID
                for ap in session.access_points.values():
                    if ap.ssid == ssid:
                        graph.edges.append(TopologyEdge(
                            source=cl.mac,
                            target=ap.bssid,
                            edge_type="probed",
                            weight=1,
                            metadata={"ssid": ssid},
                        ))
                        break

        log.info("Built topology: %d nodes, %d edges", graph.node_count, graph.edge_count)
        return graph

    def find_clusters(self, graph: TopologyGraph) -> list[list[str]]:
        """Find connected clusters in the topology.

        Returns:
            List of clusters, each being a list of node identifiers.
        """
        visited: set[str] = set()
        clusters: list[list[str]] = []

        for node_id in graph.nodes:
            if node_id in visited:
                continue

            cluster: list[str] = []
            stack = [node_id]

            while stack:
                current = stack.pop()
                if current in visited:
                    continue
                visited.add(current)
                cluster.append(current)

                for neighbor in graph.get_neighbors(current):
                    if neighbor not in visited:
                        stack.append(neighbor)

            if cluster:
                clusters.append(sorted(cluster))

        return sorted(clusters, key=len, reverse=True)

    def find_same_network_aps(self, session: ScanSession) -> dict[str, list[str]]:
        """Group APs that likely belong to the same network (same SSID).

        Returns:
            Dict of SSID -> list of BSSIDs.
        """
        ssid_groups: dict[str, list[str]] = {}
        for ap in session.access_points.values():
            if ap.ssid:
                if ap.ssid not in ssid_groups:
                    ssid_groups[ap.ssid] = []
                ssid_groups[ap.ssid].append(ap.bssid)
        return {ssid: bssids for ssid, bssids in ssid_groups.items() if len(bssids) > 1}
