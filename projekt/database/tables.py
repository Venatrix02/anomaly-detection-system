from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, Text, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from .connection import Base

class NetworkMetric(Base):
    __tablename__ = "network_metrics"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    packets_count = Column(Integer)
    connections_count = Column(Integer)
    unique_ips = Column(Integer)
    unique_ports = Column(Integer)
    avg_packet_size = Column(Float)
    tcp_ratio = Column(Float)
    udp_ratio = Column(Float)
    unique_connections = Column(Integer)
    in_out_ratio = Column(Float)
    dominant_port = Column(Integer)

class ModelInfo(Base):
    __tablename__ = "model_info"
    id = Column(Integer, primary_key=True)
    model_name = Column(String(100))
    algorithm_type = Column(String(50))
    training_date = Column(DateTime)
    parameters = Column(Text)
    accuracy = Column(Float)
    is_active = Column(Boolean, default=False)

class Anomaly(Base):
    __tablename__ = "anomalies"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    anomaly_score = Column(Float)
    severity_level = Column(String(10))  #low/medium/high
    description = Column(Text)
    metric_id = Column(Integer, ForeignKey("network_metrics.id"))
    model_id = Column(Integer, ForeignKey("model_info.id"))

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    anomaly_id = Column(Integer, ForeignKey("anomalies.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String(20), default="new")  #new/acknowledged/closed

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True)
    password_hash = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    is_active = Column(Boolean, default=True)

class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True)
    generated_at = Column(DateTime, default=datetime.utcnow)
    period_start = Column(DateTime)
    period_end = Column(DateTime)
    generated_by = Column(Integer, ForeignKey("users.id"))
    file_path = Column(String(255))
    summary = Column(Text)

class SystemLog(Base):
    __tablename__ = "system_logs"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    log_level = Column(String(10))  #INFO/WARNING/ERROR
    message = Column(Text)
