"""Tests for WarrenMap mapping components."""

import pytest

from flyinghoneysnitch.core.models import GeoPosition
from flyinghoneysnitch.mapping.gis import (
    bounding_box,
    center_point,
    haversine_distance,
    rssi_to_distance_m,
)


class TestHaversineDistance:
    def test_same_point(self):
        pos = GeoPosition(latitude=38.9072, longitude=-77.0369)
        assert haversine_distance(pos, pos) == 0.0

    def test_known_distance(self):
        # DC to NYC is approximately 328 km
        dc = GeoPosition(latitude=38.9072, longitude=-77.0369)
        nyc = GeoPosition(latitude=40.7128, longitude=-74.0060)
        dist = haversine_distance(dc, nyc)
        assert 320_000 < dist < 340_000  # 320-340 km

    def test_short_distance(self):
        pos1 = GeoPosition(latitude=38.9072, longitude=-77.0369)
        pos2 = GeoPosition(latitude=38.9073, longitude=-77.0369)
        dist = haversine_distance(pos1, pos2)
        assert 10 < dist < 15  # About 11 meters


class TestBoundingBox:
    def test_single_point(self):
        positions = [GeoPosition(latitude=38.9, longitude=-77.0)]
        south, west, north, east = bounding_box(positions, padding_m=100)
        assert south < 38.9 < north
        assert west < -77.0 < east

    def test_multiple_points(self):
        positions = [
            GeoPosition(latitude=38.9, longitude=-77.0),
            GeoPosition(latitude=38.91, longitude=-77.01),
        ]
        south, west, north, east = bounding_box(positions)
        assert south <= 38.9
        assert north >= 38.91

    def test_empty_positions(self):
        assert bounding_box([]) == (0, 0, 0, 0)


class TestCenterPoint:
    def test_center(self):
        positions = [
            GeoPosition(latitude=38.0, longitude=-77.0),
            GeoPosition(latitude=39.0, longitude=-76.0),
        ]
        center = center_point(positions)
        assert center is not None
        assert abs(center.latitude - 38.5) < 0.01
        assert abs(center.longitude - (-76.5)) < 0.01

    def test_empty(self):
        assert center_point([]) is None


class TestRssiToDistance:
    def test_strong_signal(self):
        dist = rssi_to_distance_m(-30)
        assert dist == 1.0  # At reference power

    def test_medium_signal(self):
        dist = rssi_to_distance_m(-60)
        assert 5 < dist < 20

    def test_weak_signal(self):
        dist = rssi_to_distance_m(-90)
        assert dist > 50

    def test_stronger_than_reference(self):
        dist = rssi_to_distance_m(-20)
        assert dist == 1.0  # Clamped to minimum
