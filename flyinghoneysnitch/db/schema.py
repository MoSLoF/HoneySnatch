"""SQLAlchemy ORM models for FlyingHoneySnitch database.

Each scan session is stored in a SQLite database file (.fhs).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class SessionRecord(Base):
    """A scan session record."""

    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(64), unique=True, nullable=False)
    name = Column(String(256), default="")
    interface = Column(String(64), default="")
    start_time = Column(DateTime, default=datetime.now)
    end_time = Column(DateTime, nullable=True)
    channels = Column(Text, default="")  # Comma-separated
    notes = Column(Text, default="")

    access_points = relationship("AccessPointRecord", back_populates="session", cascade="all, delete-orphan")
    clients = relationship("ClientRecord", back_populates="session", cascade="all, delete-orphan")
    positions = relationship("PositionRecord", back_populates="session", cascade="all, delete-orphan")


class AccessPointRecord(Base):
    """A discovered access point record."""

    __tablename__ = "access_points"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("sessions.id"), nullable=False)
    bssid = Column(String(17), nullable=False)
    ssid = Column(String(256), default="")
    channel = Column(Integer, default=0)
    frequency = Column(Integer, default=0)
    rssi = Column(Integer, default=-100)
    max_rssi = Column(Integer, default=-100)
    encryption = Column(String(32), default="Unknown")
    cipher = Column(String(32), default="")
    auth = Column(String(32), default="")
    band = Column(String(16), default="2.4 GHz")
    vendor = Column(String(256), default="")
    hidden = Column(Boolean, default=False)
    beacon_count = Column(Integer, default=0)
    data_count = Column(Integer, default=0)
    wps = Column(Boolean, default=False)
    first_seen = Column(DateTime, default=datetime.now)
    last_seen = Column(DateTime, default=datetime.now)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    max_rssi_latitude = Column(Float, nullable=True)
    max_rssi_longitude = Column(Float, nullable=True)

    session = relationship("SessionRecord", back_populates="access_points")
    associated_clients = relationship("ClientRecord", back_populates="associated_ap")


class ClientRecord(Base):
    """A discovered wireless client record."""

    __tablename__ = "clients"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("sessions.id"), nullable=False)
    mac = Column(String(17), nullable=False)
    bssid = Column(String(17), ForeignKey("access_points.bssid"), nullable=True)
    rssi = Column(Integer, default=-100)
    vendor = Column(String(256), default="")
    probe_requests = Column(Text, default="")  # Comma-separated SSIDs
    data_count = Column(Integer, default=0)
    first_seen = Column(DateTime, default=datetime.now)
    last_seen = Column(DateTime, default=datetime.now)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)

    session = relationship("SessionRecord", back_populates="clients")
    associated_ap = relationship("AccessPointRecord", back_populates="associated_clients", foreign_keys=[bssid])


class PositionRecord(Base):
    """GPS/IMU position track point."""

    __tablename__ = "positions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("sessions.id"), nullable=False)
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    altitude = Column(Float, nullable=True)
    accuracy = Column(Float, nullable=True)
    source = Column(String(16), default="gps")
    timestamp = Column(DateTime, default=datetime.now)

    session = relationship("SessionRecord", back_populates="positions")


class SignalRecord(Base):
    """Signal strength measurement over time for an AP."""

    __tablename__ = "signals"

    id = Column(Integer, primary_key=True, autoincrement=True)
    bssid = Column(String(17), nullable=False)
    rssi = Column(Integer, nullable=False)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    timestamp = Column(DateTime, default=datetime.now)


class AlertRecord(Base):
    """Security alert record for SentryWeb monitoring."""

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_type = Column(String(64), nullable=False)  # rogue_ap, new_client, policy_violation
    severity = Column(String(16), default="info")  # info, warning, critical
    message = Column(Text, nullable=False)
    bssid = Column(String(17), nullable=True)
    mac = Column(String(17), nullable=True)
    acknowledged = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.now)


class IsolationSessionRecord(Base):
    """An isolation testing session record."""

    __tablename__ = "isolation_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(64), unique=True, nullable=False)
    name = Column(String(256), default="")
    interface = Column(String(64), default="")
    second_interface = Column(String(64), default="")
    target_ssid = Column(String(256), default="")
    target_bssid = Column(String(17), default="")
    config_file = Column(String(512), default="")
    start_time = Column(DateTime, default=datetime.now)
    end_time = Column(DateTime, nullable=True)
    notes = Column(Text, default="")

    results = relationship(
        "IsolationResultRecord", back_populates="session",
        cascade="all, delete-orphan",
    )


class IsolationResultRecord(Base):
    """A single isolation attack test result."""

    __tablename__ = "isolation_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("isolation_sessions.id"), nullable=False)
    attack_type = Column(String(64), nullable=False)
    outcome = Column(String(32), nullable=False)
    target_bssid = Column(String(17), default="")
    target_ssid = Column(String(256), default="")
    victim_identity = Column(String(256), default="")
    attacker_identity = Column(String(256), default="")
    victim_mac = Column(String(17), default="")
    attacker_mac = Column(String(17), default="")
    details = Column(Text, default="")
    duration_seconds = Column(Float, default=0.0)
    timestamp = Column(DateTime, default=datetime.now)
    raw_log = Column(Text, default="")

    session = relationship("IsolationSessionRecord", back_populates="results")
