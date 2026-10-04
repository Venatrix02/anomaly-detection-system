import logging
import time
import os
from scapy.all import sniff, IP, TCP, UDP
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

IFACE = os.getenv("SNIFFER_IFACE", "wlo1") #interfejs sieciowy pobierany z .env

#wyciąganie najważniejszych informacji z pakietów

def process_packet(packet, packet_list):
    if IP in packet:
        tcp_flags = str(packet[TCP].flags) if TCP in packet else ""
        packet_list.append({
            "timestamp": time.time(),
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "size": len(packet),
            "protocol": "TCP" if TCP in packet else "UDP" if UDP in packet else "OTHER",
            "src_port": packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else 0,
            "dst_port": packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0,
            "tcp_flags": tcp_flags
        })

#tworzenie listy pakietów zebranych w czasie 1 sekundy

def capture_packets(duration=1):
    packet_list = []
    try:
        sniff(
            iface=IFACE,
            filter="tcp or udp",
            timeout=duration,
            prn=lambda pkt: process_packet(pkt, packet_list),
            store=False
        )
        logger.info(f"Captured {len(packet_list)} packets")
    except Exception as e:
        logger.error(f"Error during packet capture: {e}")
    return packet_list

#bezpieczne zatrzymanie sniffera

def stop_sniffer():
    logger.info("Sniffer will stop after current capture cycle.")