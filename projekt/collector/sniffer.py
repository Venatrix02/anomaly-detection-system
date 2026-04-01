import logging
from scapy.all import sniff, IP, TCP, UDP

logger = logging.getLogger(__name__)

def process_packet(packet, packet_list):
    if IP in packet:
        packet_list.append({
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "size": len(packet),
            "protocol": "TCP" if TCP in packet else "UDP" if UDP in packet else "OTHER",
            "src_port": packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else 0,
            "dst_port": packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0,
        })

def capture_packets(duration=10):
    packet_list = []
    try:
        sniff(
            filter="tcp or udp",
            timeout=duration,
            prn=lambda pkt: process_packet(pkt, packet_list),
            store=False
        )
        logger.info(f"Przechwycono {len(packet_list)} pakietów")
    except Exception as e:
        logger.error(f"Błąd podczas przechwytywania pakietów: {e}")
    return packet_list