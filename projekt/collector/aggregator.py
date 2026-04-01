import logging
from collections import Counter
from database.connection import SessionLocal
from database.tables import NetworkMetric, SystemLog

logger = logging.getLogger(__name__)

def save_log_to_db(session, level, message):
    log = SystemLog(log_level=level, message=message)
    session.add(log)
    session.commit()

def aggregate_and_save(packet_list):
    if not packet_list:
        logger.warning("No packets to aggregate")
        return

    total = len(packet_list)
    unique_ips = len(
        set(p["src_ip"] for p in packet_list) | set(p["dst_ip"] for p in packet_list)
    )
    unique_ports = len(set(p["dst_port"] for p in packet_list))
    avg_size = sum(p["size"] for p in packet_list) / total
    tcp_count = sum(1 for p in packet_list if p["protocol"] == "TCP")
    udp_count = sum(1 for p in packet_list if p["protocol"] == "UDP")
    unique_connections = len(set((p["src_ip"], p["dst_ip"]) for p in packet_list))
    incoming = sum(1 for p in packet_list if p["dst_ip"].startswith("192.168.0"))
    outgoing = total - incoming
    in_out_ratio = round(incoming / total, 2) if total > 0 else 0
    port_counter = Counter(p["dst_port"] for p in packet_list)
    most_common = port_counter.most_common(1) 
    dominant_port = most_common[0][0] if most_common else 0

    metric = NetworkMetric(
        packets_count=total,
        connections_count=total,
        unique_ips=unique_ips,
        unique_ports=unique_ports,
        avg_packet_size=round(avg_size, 2),
        tcp_ratio=round(tcp_count / total, 2),
        udp_ratio=round(udp_count / total, 2),
        unique_connections=unique_connections,
        in_out_ratio=in_out_ratio,
        dominant_port=dominant_port,
    )

    session = SessionLocal()
    try:
        session.add(metric)
        session.commit()
        msg = f"Metric saved: {total} packets, {unique_ips} unique IPs"
        logger.info(msg)
        save_log_to_db(session, "INFO", msg)
    except Exception as e:
        session.rollback()
        logger.error(f"Error saving metric: {e}")
        save_log_to_db(session, "ERROR", str(e))
    finally:
        session.close()