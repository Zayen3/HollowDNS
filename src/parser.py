"""
parser.py

Reads DNS packets from a PCAP file and converts them into
a standardized DNS query format for the detection pipeline.
"""

from scapy.all import rdpcap

from utils import extract_dns_query

PCAP_FILE = "data/sample.pcapng"


def load_pcap():
    """
    Load packets from the PCAP file.
    """
    packets = rdpcap(PCAP_FILE)
    print(f"Successfully loaded {len(packets)} packets.")
    return packets


def extract_dns_queries(packets):
    """
    Extract DNS queries from a packet list.

    Returns a list of dictionaries in the standard format:
    {
        "timestamp": float,
        "domain": str,
        "source_ip": str,
        "destination_ip": str
    }
    """
    dns_queries = []

    for packet in packets:
        query = extract_dns_query(packet)

        if query is not None:
            dns_queries.append(query)

    print(f"Found {len(dns_queries)} DNS queries.\n")
    return dns_queries


if __name__ == "__main__":
    packets = load_pcap()
    dns_queries = extract_dns_queries(packets)