"""
Feature Extraction Module

This module extracts features from DNS queries that are
used by the DNS tunneling detection engine.
"""

from entropy import calculate_entropy
from whitelist import (
    IGNORED_PREFIXES,
    IGNORED_SUFFIXES,
)


def get_subdomain(domain):
    """
    Return the left-most DNS label.

    Example:
        mail.google.com -> mail
        abc123.attacker.com -> abc123
    """
    return domain.split(".")[0]


def get_parent_domain(domain):
    """
    Return the registered (parent) domain.

    Example:
        mail.google.com -> google.com
        docs.github.com -> github.com
        attacker.com -> attacker.com
    """

    labels = domain.split(".")

    if len(labels) >= 2:
        return ".".join(labels[-2:])

    return domain

def should_ignore_domain(domain):

    domain = domain.lower()

    if any(domain.endswith(suffix) for suffix in IGNORED_SUFFIXES):
        return True

    subdomain = get_subdomain(domain)

    if any(subdomain.startswith(prefix) for prefix in IGNORED_PREFIXES):
        return True

    return False


def calculate_subdomain_entropy(domain):
    """
    Calculate the Shannon entropy of the subdomain.
    """

    return calculate_entropy(get_subdomain(domain))


def get_subdomain_length(domain):
    """
    Return the length of the subdomain.
    """

    return len(get_subdomain(domain))


def get_domain_length(domain):
    """
    Return the total length of the full domain.
    """

    return len(domain)


def get_dns_label_count(domain):
    """
    Count the total number of DNS labels.

    Example:
        mail.google.com -> 3
        chatgpt.com -> 2
    """

    return len(domain.split("."))


def extract_features(query):
    """
    Extract all DNS features from a query.

    Parameters
    ----------
    query : dict
        Dictionary returned by parser.py.

    Returns
    -------
    dict
        Dictionary containing the original query information
        along with extracted DNS features.
    """

    domain = query["domain"]
    if should_ignore_domain(domain):
        return None

    # Keep all original parser fields
    features = query.copy()

    # Add extracted features
    features["subdomain"] = get_subdomain(domain)
    features["parent_domain"] = get_parent_domain(domain)
    features["entropy"] = calculate_subdomain_entropy(domain)
    features["subdomain_length"] = get_subdomain_length(domain)
    features["domain_length"] = get_domain_length(domain)
    features["dns_label_count"] = get_dns_label_count(domain)

    return features