"""
ui.py

Rich terminal user interface for the DNS Tunneling Detector.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.columns import Columns
from rich.text import Text
from rich.rule import Rule
from rich import box
from collections import Counter
from rich.prompt import Prompt

console = Console()


# ============================================================
# Banner
# ============================================================

def show_banner():

    title = Text(
        "DNS TUNNELING DETECTOR",
        justify="center",
        style="bold bright_cyan",
    )

    subtitle = Text(
        "Behavioural DNS Threat Detection Engine",
        justify="center",
        style="green",
    )

    banner = Panel(
        Align.center(
            Text("\n").join([title, subtitle])
        ),
        border_style="bright_blue",
        box=box.DOUBLE,
        padding=(1, 6),
    )

    console.print(banner)
    console.print()


# ============================================================
# Analysis Information
# ============================================================

def show_analysis_information(
    packet_count,
    dns_queries,
    threat_summary,
):

    console.print(
        Rule(
            "[bold cyan]Analysis Information[/bold cyan]"
        )
    )

    table = Table(
        show_header=False,
        box=box.SIMPLE_HEAVY,
        expand=True,
    )

    table.add_column(style="cyan", width=28)
    table.add_column(style="white")

    table.add_row(
        "Analysis Mode",
        "Offline PCAP"
    )

    table.add_row(
        "Capture File",
        "sample.pcapng"
    )

    table.add_row(
        "Packets Analysed",
        f"{packet_count:,}"
    )

    table.add_row(
        "DNS Queries",
        str(dns_queries)
    )

    table.add_row(
        "Unique Parent Domains",
        str(threat_summary["unique_parent_domains"])
    )

    table.add_row(
        "Unique Domains",
        str(threat_summary["unique_domains"])
    )

    console.print(table)
    console.print()


# ============================================================
# Executive Summary
# ============================================================

def show_executive_summary(summary):

    console.print(
        Rule(
            "[bold red]Executive Summary[/bold red]"
        )
    )

    risk_colour = {
        "LOW": "green",
        "MEDIUM": "yellow",
        "HIGH": "red",
        "CRITICAL": "bright_red",
    }.get(summary["overall_risk"], "white")

    cards = [

        Panel(
            f"[bold]{summary['overall_risk']}[/bold]",
            title="Overall Risk",
            border_style=risk_colour,
        ),

        Panel(
            str(summary["total_queries"]),
            title="DNS Queries",
            border_style="cyan",
        ),

        Panel(
            str(summary["suspicious_queries"]),
            title="Suspicious",
            border_style="red",
        ),

        Panel(
            f"{summary['average_entropy']:.2f}",
            title="Avg Entropy",
            border_style="magenta",
        ),
    ]

    console.print(
        Columns(
            cards,
            equal=True,
            expand=True,
        )
    )

    console.print()


# ============================================================
# Threat Overview
# ============================================================

def show_threat_overview(suspicious_queries):

    console.print(
        Rule(
            "[bold yellow]Threat Overview[/bold yellow]"
        )
    )

    counts = Counter(
        query["severity"]
        for query in suspicious_queries
    )

    table = Table(
        box=box.ROUNDED,
        border_style="yellow",
        expand=True,
    )

    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="center")
    table.add_column("Visual")

    levels = [
        ("CRITICAL", "bright_red"),
        ("HIGH", "red"),
        ("MEDIUM", "yellow"),
        ("LOW", "green"),
    ]

    for level, colour in levels:

        value = counts.get(level, 0)

        table.add_row(
            f"[{colour}]{level}[/{colour}]",
            str(value),
            f"[{colour}]{'█' * value}[/{colour}]"
            if value
            else "-"
        )

    console.print(table)
    console.print()


# ============================================================
# Top Security Findings
# ============================================================

def show_top_security_findings(suspicious_queries):

    console.print(
        Rule("[bold red]Top Security Findings[/bold red]")
    )

    table = Table(
        box=box.ROUNDED,
        border_style="red",
        expand=True,
    )

    table.add_column("#", justify="center", width=3)
    table.add_column("Severity", width=10)
    table.add_column("Domain", overflow="fold")
    table.add_column("Entropy", justify="center", width=8)
    table.add_column("Score", justify="center", width=6)

    if not suspicious_queries:

        table.add_row(
            "-",
            "None",
            "No suspicious domains detected.",
            "-",
            "-",
        )

    else:

        for index, query in enumerate(suspicious_queries[:10], start=1):

            severity = query["severity"]

            colour = {
                "CRITICAL": "bright_red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "green",
            }.get(severity, "white")

            table.add_row(
                str(index),
                f"[{colour}]{severity}[/{colour}]",
                query["domain"],
                f"{query['entropy']:.2f}",
                str(query["score"]),
            )

    console.print(table)
    console.print()
# ============================================================
# Capture Summary
# ============================================================

def show_capture_summary(packet_count, dns_count):

    table = Table(
        title="[bold cyan]Capture Summary[/bold cyan]",
        show_header=False,
        box=None,
    )

    table.add_column(style="cyan")
    table.add_column(style="white")

    table.add_row("📂 Capture File", "sample.pcapng")
    table.add_row("📦 Packets Loaded", f"{packet_count:,}")
    table.add_row("🌐 DNS Queries", str(dns_count))

    console.print(table)
    console.print()


# ============================================================
# Detection Summary
# ============================================================

def show_detection_summary(
    unique_domains,
    average_entropy,
    highest_entropy,
):

    table = Table(
        title="[bold cyan]Detection Summary[/bold cyan]",
        show_header=False,
        box=None,
    )

    table.add_column(style="cyan")
    table.add_column(style="white")

    table.add_row(
        "Unique Domains",
        str(unique_domains)
    )

    table.add_row(
        "Average Entropy",
        f"{average_entropy:.2f}"
    )

    if highest_entropy:

        table.add_row(
            "Highest Entropy",
            f"{highest_entropy['entropy']:.2f}"
        )

        table.add_row(
            "Highest Entropy Domain",
            highest_entropy["domain"]
        )

    else:

        table.add_row(
            "Highest Entropy",
            "-"
        )

        table.add_row(
            "Highest Entropy Domain",
            "-"
        )

    console.print(table)
    console.print()


# ============================================================
# Top Queried Domains
# ============================================================

def show_top_domains(top_domains):

    table = Table(
        title="[bold green]Top Queried Domains[/bold green]",
        border_style="green",
    )

    table.add_column(
        "Rank",
        justify="center",
        style="cyan"
    )

    table.add_column(
        "Parent Domain",
        style="white"
    )

    table.add_column(
        "Queries",
        justify="center",
        style="green"
    )

    for rank, (domain, count) in enumerate(
        top_domains,
        start=1
    ):

        table.add_row(
            str(rank),
            domain,
            str(count)
        )

    console.print(table)
    console.print()


# ============================================================
# Unique Subdomains
# ============================================================

def show_unique_subdomains(unique_subdomains):

    table = Table(
        title="[bold magenta]Unique Subdomain Analysis[/bold magenta]",
        border_style="magenta",
    )

    table.add_column(
        "Parent Domain",
        style="cyan"
    )

    table.add_column(
        "Unique Subdomains",
        justify="center",
        style="yellow"
    )

    if not unique_subdomains:

        table.add_row(
            "-",
            "None"
        )

    else:

        for item in unique_subdomains:

            table.add_row(
                item["parent_domain"],
                str(item["unique_subdomains"])
            )

    console.print(table)
    console.print()


# ============================================================
# Threat Report
# ============================================================

def show_threat_report(suspicious_queries):

    table = Table(
        title="[bold red]Threat Report[/bold red]",
        border_style="red",
        show_lines=True,
    )

    table.add_column(
        "Severity",
        justify="center",
        style="bold",
        width=12,
    )

    table.add_column(
        "Domain",
        style="cyan",
        overflow="fold",
        width=42,
    )

    table.add_column(
        "Entropy",
        justify="center",
        width=8,
    )

    table.add_column(
        "Frequency",
        justify="center",
        width=9,
    )

    table.add_column(
        "Indicators",
        style="yellow",
        overflow="fold",
        width=35,
    )

    if not suspicious_queries:

        table.add_row(
            "[green]NONE[/green]",
            "-",
            "-",
            "-",
            "No suspicious DNS behaviour detected."
        )

    else:

        for query in suspicious_queries:

            trusted = query.get("is_trusted", False)

            if trusted:

                severity_text = "[bold green]TRUSTED[/bold green]"

            else:

                severity = query["severity"]

                if severity == "CRITICAL":
                    severity_text = "[bold bright_red]CRITICAL[/bold bright_red]"

                elif severity == "HIGH":
                    severity_text = "[bold red]HIGH[/bold red]"

                elif severity == "MEDIUM":
                    severity_text = "[bold yellow]MEDIUM[/bold yellow]"

                else:
                    severity_text = "[cyan]LOW[/cyan]"

            indicators = "\n".join(
                f"• {item}"
                for item in query["indicators"]
            )

            if trusted:

                indicators += (
                    "\n[green]• Trusted Infrastructure[/green]"
                )

            table.add_row(

                severity_text,

                query["domain"],

                f"{query['entropy']:.2f}",

                str(query["frequency"]),

                indicators,

            )

    console.print(table)
    console.print()


# ============================================================
# Live Alert
# ============================================================

def show_live_alert(alert):

    console.rule("[bold red]LIVE ALERT[/bold red]")

    trusted = alert.get("is_trusted", False)

    if trusted:

        console.print(
            "[bold green]Status      : Trusted Infrastructure[/bold green]"
        )

    else:

        console.print(
            f"[bold red]Severity    : {alert['severity']}[/bold red]"
        )

    console.print(
        f"[cyan]Domain      :[/cyan] {alert['domain']}"
    )

    console.print(
        f"[cyan]Entropy     :[/cyan] {alert['entropy']:.2f}"
    )

    console.print(
        f"[cyan]Frequency   :[/cyan] {alert['frequency']}"
    )

    console.print(
        f"[cyan]Unique Subs :[/cyan] {alert['unique_subdomains']}"
    )

    console.print(
        f"[cyan]Indicators  :[/cyan] "
        + ", ".join(alert["indicators"])
    )

    if trusted:

        console.print(
            "[green]Reason      : Known trusted infrastructure[/green]"
        )

    console.print()
# ============================================================
# DNS Feature Analysis
# ============================================================

def show_feature_table(features):

    table = Table(
        title="[bold cyan]DNS Feature Analysis[/bold cyan]",
        border_style="bright_blue",
    )

    table.add_column("#", justify="right", style="cyan")
    table.add_column("Domain", width=42, overflow="fold")
    table.add_column("Entropy", justify="center")
    table.add_column("Sub Len", justify="center")
    table.add_column("Domain Len", justify="center")
    table.add_column("Labels", justify="center")

    for index, feature in enumerate(features[:20], start=1):

        table.add_row(
            str(index),
            feature["domain"],
            f"{feature['entropy']:.2f}",
            str(feature["subdomain_length"]),
            str(feature["domain_length"]),
            str(feature["dns_label_count"]),
        )

    console.print(table)

    if len(features) > 20:

        console.print(
            f"[dim]{len(features) - 20} additional queries omitted...[/dim]"
        )

    console.print()


# ============================================================
# Live Monitoring Summary
# ============================================================

def show_live_summary(state):

    console.rule("[bold cyan]LIVE MONITORING SUMMARY[/bold cyan]")

    console.print(
        f"[cyan]Total DNS Queries       :[/cyan] {state.total_queries}"
    )

    console.print(
        f"[cyan]Unique Domains         :[/cyan] {len(state.unique_domains)}"
    )

    console.print(
        f"[cyan]Unique Parent Domains  :[/cyan] {len(state.unique_parent_domains)}"
    )

    console.print(
        f"[cyan]Average Entropy       :[/cyan] {state.average_entropy:.2f}"
    )

    console.print(
        f"[cyan]Alerts Generated      :[/cyan] {len(state.suspicious_queries)}"
    )

    console.print()

    if state.severity_counts:

        table = Table(
            title="[bold yellow]Severity Distribution[/bold yellow]"
        )

        table.add_column("Severity", style="cyan")
        table.add_column("Count", justify="center")

        for severity in [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW"
        ]:

            table.add_row(
                severity,
                str(state.severity_counts.get(severity, 0))
            )

        console.print(table)

    console.print()


# ============================================================
# Security Recommendations
# ============================================================

def show_security_recommendations(summary):

    risk = summary["overall_risk"]

    recommendations = []

    if risk == "CRITICAL":

        recommendations = [
            "Immediate investigation recommended.",
            "Review suspicious DNS queries.",
            "Check affected endpoints.",
            "Consider blocking malicious domains.",
        ]

    elif risk == "HIGH":

        recommendations = [
            "Investigate suspicious DNS behaviour.",
            "Review DNS logs.",
            "Monitor affected hosts closely.",
        ]

    elif risk == "MEDIUM":

        recommendations = [
            "Review flagged domains.",
            "Continue monitoring for recurring activity.",
        ]

    else:

        recommendations = [
            "No significant malicious DNS behaviour detected.",
            "Continue routine monitoring.",
        ]

    panel = Panel(
        "\n".join(
            f"• {item}"
            for item in recommendations
        ),
        title=f"Security Recommendations ({risk} Risk)",
        border_style="green"
    )

    console.print(panel)
    console.print()


# ============================================================
# Evaluation Summary
# ============================================================

def show_evaluation_summary(summary):

    console.print(
        Rule("[bold bright_magenta]Evaluation Summary[/bold bright_magenta]")
    )

    total = summary["total_queries"]
    suspicious = summary["suspicious_queries"]

    detection_rate = (
        (suspicious / total) * 100
        if total else 0
    )

    table = Table(
        box=box.ROUNDED,
        border_style="bright_magenta",
        expand=True,
    )

    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")

    table.add_row(
        "Total DNS Queries",
        str(total)
    )

    table.add_row(
        "Suspicious Queries",
        str(suspicious)
    )

    table.add_row(
        "Detection Rate",
        f"{detection_rate:.2f}%"
    )

    table.add_row(
        "Detection Method",
        "Rule-Based + Behaviour Analysis"
    )

    console.print(table)
    console.print()


# ============================================================
# Mode Selection
# ============================================================

def show_mode_selection():

    table = Table(
        title="[bold cyan]Select Analysis Mode[/bold cyan]",
        box=box.ROUNDED,
        border_style="bright_blue",
    )

    table.add_column("Option", justify="center", style="cyan")
    table.add_column("Mode", style="white")
    table.add_column("Description", style="green")

    table.add_row(
        "1",
        "Offline PCAP",
        "Analyse captured DNS traffic"
    )

    table.add_row(
        "2",
        "Live Monitoring",
        "Monitor DNS traffic in real time"
    )

    console.print(table)

    return Prompt.ask(
        "[bold cyan]Select Mode[/bold cyan]",
        choices=["1", "2"]
    )


# ============================================================
# Simple Messages
# ============================================================

def show_info(message):
    console.print(f"[cyan]{message}[/cyan]")


def show_success(message):
    console.print(f"[bold green]{message}[/bold green]")


def show_warning(message):
    console.print(f"[bold yellow]{message}[/bold yellow]")


def show_error(message):
    console.print(f"[bold red]{message}[/bold red]")


# ============================================================
# Public API
# ============================================================

__all__ = [

    "show_banner",

    "show_analysis_information",

    "show_executive_summary",

    "show_threat_overview",

    "show_top_security_findings",

    "show_top_domains",

    "show_unique_subdomains",

    "show_threat_report",

    "show_feature_table",

    "show_security_recommendations",

    "show_evaluation_summary",

    "show_live_alert",

    "show_live_summary",

    "show_mode_selection",

    "show_info",

    "show_success",

    "show_warning",

    "show_error",

]