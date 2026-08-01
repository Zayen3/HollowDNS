"""
sniffer.py

Live DNS packet sniffer for the DNS Tunneling Detector.
"""

from scapy.all import sniff
from rich.console import Console

from utils import extract_dns_query
from ui import (
    show_live_alert,
    show_live_summary,
)

console = Console()


# ==========================================================
# Live DNS Sniffer
# ==========================================================

def start_sniffing(packet_callback, interface=None, state=None):
    """
    Start live DNS packet sniffing.

    Args:
        packet_callback:
            Function called for every DNS query found.

        interface:
            Network interface.

        state:
            DetectorState object used for the
            live monitoring summary.
    """

    console.rule("[bold cyan]LIVE DNS MONITORING[/bold cyan]")

    console.print(
        "[green]Status      :[/green] Monitoring Active"
    )

    console.print(
        "[cyan]Protocol    :[/cyan] DNS"
    )

    console.print(
        f"[cyan]Interface   :[/cyan] {interface or 'Default Network Interface'}"
    )

    console.print(
        "[yellow]Press Ctrl+C to stop monitoring.[/yellow]\n"
    )

    def process_packet(packet):

        query = extract_dns_query(packet)

        if query is None:
            return

        result = packet_callback(query)

        if result:
            show_live_alert(result)

    try:

        sniff(
            iface=interface,
            filter="udp port 53",
            prn=process_packet,
            store=False,
        )

    except KeyboardInterrupt:

        console.print(
            "\n[bold yellow]Live monitoring stopped.[/bold yellow]\n"
        )

        if state is not None:
            show_live_summary(state)