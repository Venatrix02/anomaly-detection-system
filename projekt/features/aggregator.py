from collections import Counter

def aggregate_packets(packet_list):
    if not packet_list:
        return None

    total_packets = len(packet_list)

    unique_ips = len(
        set(p["src_ip"] for p in packet_list) |
        set(p["dst_ip"] for p in packet_list)
    )

    unique_ports = len(
        set(p["src_port"] for p in packet_list) |
        set(p["dst_port"] for p in packet_list)
    )

    average_packet_size = sum(p["size"] for p in packet_list) / total_packets

    tcp_packets = sum(1 for p in packet_list if p["protocol"] == "TCP")
    udp_packets = sum(1 for p in packet_list if p["protocol"] == "UDP")
    other_packets = sum(1 for p in packet_list if p["protocol"] == "OTHER")

    unique_connections = len(
        set(
            (
                p["src_ip"],
                p["dst_ip"],
                p["src_port"],
                p["dst_port"],
                p["protocol"]
            )
            for p in packet_list
        )
    )

    destination_port_counter = Counter(
        p["dst_port"] for p in packet_list if p["dst_port"] != 0
    )
    most_common_port = destination_port_counter.most_common(1)
    dominant_destination_port = most_common_port[0][0] if most_common_port else 0

    synchronization_packets_count = sum(
        1 for p in packet_list
        if p["tcp_flags"] and "S" in p["tcp_flags"] and "A" not in p["tcp_flags"]
    )

    acknowledgment_packets_count = sum(
        1 for p in packet_list
        if p["tcp_flags"] and "A" in p["tcp_flags"]
    )

    reset_packets_count = sum(
        1 for p in packet_list
        if p["tcp_flags"] and "R" in p["tcp_flags"]
    )

    finish_packets_count = sum(
        1 for p in packet_list
        if p["tcp_flags"] and "F" in p["tcp_flags"]
    )

    window_start = min(p["timestamp"] for p in packet_list)
    window_end = max(p["timestamp"] for p in packet_list)

    return {
        "window_start": window_start,
        "window_end": window_end,
        "packets_count": total_packets,
        "unique_ips": unique_ips,
        "unique_ports": unique_ports,
        "avg_packet_size": round(average_packet_size, 2),
        "tcp_ratio": round(tcp_packets / total_packets, 2),
        "udp_ratio": round(udp_packets / total_packets, 2),
        "other_ratio": round(other_packets / total_packets, 2),
        "unique_connections": unique_connections,
        "dominant_port": dominant_destination_port,
        "synchronization_packets_count": synchronization_packets_count,
        "acknowledgment_packets_count": acknowledgment_packets_count,
        "reset_packets_count": reset_packets_count,
        "finish_packets_count": finish_packets_count
    }