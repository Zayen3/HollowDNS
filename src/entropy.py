"""
entropy.py

Provides functionality to calculate the Shannon entropy
of DNS subdomains or any given string.
"""

import math
from collections import Counter


def calculate_entropy(text: str) -> float:
    """
    Calculate the Shannon entropy of a string.

    Higher entropy generally indicates more randomness,
    which can be a useful indicator of encoded or tunneled
    DNS data.

    Args:
        text (str): Input string.

    Returns:
        float: Shannon entropy rounded to two decimal places.
    """

    if not text:
        return 0.0

    character_counts = Counter(text)
    text_length = len(text)

    entropy = 0.0

    for count in character_counts.values():
        probability = count / text_length
        entropy -= probability * math.log2(probability)

    return round(entropy, 2)