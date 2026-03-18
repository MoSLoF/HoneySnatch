"""Tests for HoneyView analysis components."""

import pytest

from honeysnatch.analysis.patterns import PatternAnalyzer, _is_randomized_mac
from honeysnatch.analysis.profiles import ProfileEngine, PROFILE_OPEN_NETWORKS
from honeysnatch.analysis.topology import TopologyBuilder
from honeysnatch.core.models import AccessPoint, Client, EncryptionType, ScanSession


class TestPatternAnalyzer:
    def test_probe_patterns(self, sample_session):
        analyzer = PatternAnalyzer(sample_session)
        profiles = analyzer.analyze_probe_patterns()
        assert len(profiles) >= 1
        assert profiles[0].unique_probes >= 1

    def test_network_profiles(self, sample_session):
        analyzer = PatternAnalyzer(sample_session)
        networks = analyzer.analyze_network_profiles()
        assert len(networks) >= 1

    def test_encryption_summary(self, sample_session):
        analyzer = PatternAnalyzer(sample_session)
        summary = analyzer.encryption_summary()
        assert "WPA2" in summary
        assert "Open" in summary

    def test_evil_twin_detection(self):
        session = ScanSession(session_id="test", name="Test")
        # Two APs with same SSID but different encryption
        session.add_ap(AccessPoint(
            bssid="00:11:22:33:44:55",
            ssid="CorporateWifi",
            encryption=EncryptionType.WPA2,
        ))
        session.add_ap(AccessPoint(
            bssid="aa:bb:cc:dd:ee:ff",
            ssid="CorporateWifi",
            encryption=EncryptionType.OPEN,
        ))

        analyzer = PatternAnalyzer(session)
        twins = analyzer.find_potential_evil_twins()
        assert len(twins) >= 1
        assert twins[0]["risk"] == "high"


class TestRandomizedMac:
    def test_normal_mac(self):
        assert not _is_randomized_mac("00:11:22:33:44:55")

    def test_randomized_mac(self):
        # Bit 1 of first octet set = locally administered
        assert _is_randomized_mac("02:11:22:33:44:55")
        assert _is_randomized_mac("06:11:22:33:44:55")
        assert _is_randomized_mac("0a:11:22:33:44:55")

    def test_invalid_mac(self):
        assert not _is_randomized_mac("")
        assert not _is_randomized_mac("invalid")


class TestProfileEngine:
    def test_filter_open_networks(self, sample_session):
        engine = ProfileEngine()
        aps = list(sample_session.access_points.values())
        open_aps = engine.filter_aps(aps, PROFILE_OPEN_NETWORKS)
        assert len(open_aps) == 1
        assert open_aps[0].encryption == EncryptionType.OPEN

    def test_security_score_open(self, sample_open_ap):
        engine = ProfileEngine()
        score = engine.security_score(sample_open_ap)
        assert score < 30  # Open networks get low score

    def test_security_score_wpa2(self, sample_ap):
        engine = ProfileEngine()
        score = engine.security_score(sample_ap)
        assert score >= 60  # WPA2 networks get decent score

    def test_classify_ap(self, sample_open_ap):
        engine = ProfileEngine()
        classes = engine.classify_ap(sample_open_ap)
        assert "Open Networks" in classes


class TestTopologyBuilder:
    def test_build_topology(self, sample_session):
        builder = TopologyBuilder()
        graph = builder.build(sample_session)

        assert graph.node_count >= 3  # At least 3 APs
        assert graph.edge_count >= 0

    def test_find_clusters(self, sample_session):
        builder = TopologyBuilder()
        graph = builder.build(sample_session)
        clusters = builder.find_clusters(graph)
        assert len(clusters) >= 1

    def test_same_network_aps(self):
        session = ScanSession(session_id="test", name="Test")
        session.add_ap(AccessPoint(bssid="00:00:00:00:00:01", ssid="SameNet", channel=1))
        session.add_ap(AccessPoint(bssid="00:00:00:00:00:02", ssid="SameNet", channel=6))
        session.add_ap(AccessPoint(bssid="00:00:00:00:00:03", ssid="Different", channel=11))

        builder = TopologyBuilder()
        groups = builder.find_same_network_aps(session)
        assert "SameNet" in groups
        assert len(groups["SameNet"]) == 2
