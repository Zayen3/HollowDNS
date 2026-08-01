"""
utils.py

Shared utility functions used across the DNS Tunneling Detector.
"""

from scapy.all import DNS, DNSQR, IP


def extract_dns_query(packet):
    """
    Extract a DNS query from a Scapy packet.

    Returns:
        dict containing:
        {
            "timestamp": float,
            "domain": str,
            "source_ip": str,
            "destination_ip": str
        }

        or None if the packet is not a DNS query.
    """

    # Ensure this is a DNS query packet
    if not (packet.haslayer(DNS) and packet.haslayer(DNSQR)):
        return None

    if packet[DNS].qr != 0:
        return None

    domain = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")

    source_ip = (
        packet[IP].src
        if packet.haslayer(IP)
        else "Unknown"
    )

    destination_ip = (
        packet[IP].dst
        if packet.haslayer(IP)
        else "Unknown"
    )

    return {
        "timestamp": float(packet.time),
        "domain": domain,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
    }