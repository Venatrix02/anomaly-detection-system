from sqlalchemy import Column, Integer, String, Float, Double, DateTime, Boolean, Text, ForeignKey
from datetime import datetime
from .connection import Base

#tabela z podsumowaniami ruchu sieciowego (jedno podsumowanie dla każdego okresu czasu - co 10 sekund ruchu)

class NetworkMetric(Base):
    __tablename__ = "network_metrics"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

    window_start = Column(Double)
    window_end = Column(Double)

    packets_count = Column(Integer)
    unique_ips = Column(Integer)
    unique_ports = Column(Integer)
    avg_packet_size = Column(Float)

    tcp_ratio = Column(Float)
    udp_ratio = Column(Float)
    other_ratio = Column(Float)

    unique_connections = Column(Integer)
    dominant_port = Column(Integer)

    synchronization_packets_count = Column(Integer)
    acknowledgment_packets_count = Column(Integer)
    reset_packets_count = Column(Integer)
    finish_packets_count = Column(Integer)

#tabela z informacjami o modelu uczenia maszynowego wykrywającego anomalie

class ModelInfo(Base):
    __tablename__ = "model_info"

    id = Column(Integer, primary_key=True)
    model_name = Column(String(100))
    algorithm_type = Column(String(50))
    training_date = Column(DateTime)
    parameters = Column(Text)
    accuracy = Column(Float)
    is_active = Column(Boolean, default=False)

#tabela z wykrytymi anomaliami w ruchu sieciowym

class Anomaly(Base):
    __tablename__ = "anomalies"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    anomaly_score = Column(Float)
    severity_level = Column(String(10))
    description = Column(Text)
    metric_id = Column(Integer, ForeignKey("network_metrics.id"))
    model_id = Column(Integer, ForeignKey("model_info.id"))

#tabela z alertami generowanymi w przypadku wykrycia anomalii

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True)
    anomaly_id = Column(Integer, ForeignKey("anomalies.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String(20), default="new")

#tabela z użytkownikami systemu i ich danymi logowania

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True)
    password_hash = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    is_active = Column(Boolean, default=True)

#tabela z raportami

class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True)
    generated_at = Column(DateTime, default=datetime.utcnow)
    period_start = Column(DateTime)
    period_end = Column(DateTime)
    generated_by = Column(Integer, ForeignKey("users.id"))
    file_path = Column(String(255))
    summary = Column(Text)

#tabela z logami systemowymi

class SystemLog(Base):
    __tablename__ = "system_logs"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    log_level = Column(String(10))
    message = Column(Text)