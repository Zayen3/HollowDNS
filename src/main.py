"""
main.py

Entry point for the DNS Tunneling Detector.

Supports:
1. PCAP Analysis
2. Live DNS Monitoring
"""

from parser import load_pcap, extract_dns_queries
from sniffer import start_sniffing

from features import extract_features

from detector import (
    DetectorState,
    process_live_query,
    calculate_query_frequency,
    get_top_domains,
    count_unique_full_domains,
    get_highest_entropy_query,
    calculate_average_entropy,
    find_unique_subdomain_candidates,
    detect_suspicious_queries,
    generate_threat_summary,
)

from ui import (
    show_banner,
    show_mode_selection,
    show_analysis_information,
    show_executive_summary,
    show_threat_overview,
    show_top_security_findings,
    show_top_domains,
    show_unique_subdomains,
    show_threat_report,
    show_feature_table,
    show_security_recommendations,
    show_live_alert,
    show_live_summary,
)

# ==========================================================
# Live Detection State
# ==========================================================

detector_state = DetectorState()

already_reported = set()


# ==========================================================
# Offline Analysis (PCAP)
# ==========================================================

def run_analysis(dns_queries, packet_count=None):

    if not dns_queries:
        return

    features = []

    for query in dns_queries:

        feature = extract_features(query)

        if feature is not None:
            features.append(feature)

    query_frequency = calculate_query_frequency(features)

    top_domains = get_top_domains(query_frequency)

    unique_domains = count_unique_full_domains(features)

    highest_entropy = get_highest_entropy_query(features)

    average_entropy = calculate_average_entropy(features)

    unique_subdomains = find_unique_subdomain_candidates(features)

    suspicious_queries = detect_suspicious_queries(features)

    threat_summary = generate_threat_summary(
        features,
        suspicious_queries,
    )

    # ==================================================
    # Report
    # ==================================================

    show_analysis_information(
        packet_count=packet_count,
        dns_queries=len(dns_queries),
        threat_summary=threat_summary,
    )

    show_executive_summary(threat_summary)

    show_threat_overview(suspicious_queries)

    show_top_security_findings(suspicious_queries)

    show_top_domains(top_domains)

    show_unique_subdomains(unique_subdomains)

    show_threat_report(suspicious_queries)

    show_feature_table(features)

    show_security_recommendations(threat_summary)


# ==========================================================
# Live Packet Callback
# ==========================================================

def live_packet_callback(query):

    feature = extract_features(query)

    # Ignore filtered domains (.local, _tcp, etc.)
    if feature is None:
        return None

    detection = process_live_query(
        feature,
        detector_state,
    )

    if detection is None:
        return None

    domain = detection["domain"]

    if domain in already_reported:
        return None

    already_reported.add(domain)

    return detection


# ==========================================================
# Main
# ==========================================================

def main():

    show_banner()

    choice = show_mode_selection()

    # ==================================================
    # PCAP MODE
    # ==================================================

    if choice == "1":

        packets = load_pcap()

        dns_queries = extract_dns_queries(packets)

        run_analysis(
            dns_queries,
            packet_count=len(packets),
        )

    # ==================================================
    # LIVE MODE
    # ==================================================

    elif choice == "2":

        start_sniffing(
            packet_callback=live_packet_callback,
            state=detector_state,
        )


if __name__ == "__main__":
    main()