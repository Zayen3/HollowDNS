from collections import Counter, defaultdict, deque
from statistics import mean
from whitelist import (
    TRUSTED_PARENT_DOMAINS,
    IGNORED_PREFIXES,
    IGNORED_SUFFIXES,
)
#from unittest import result

#import entropy
#import features

# ============================================================
# Detection Thresholds
# ============================================================

THRESHOLDS = {
    "entropy": 3.4,
    "subdomain_length": 20,
    "query_frequency": 15,
    "unique_subdomains": 10,
    "beacon_interval_variance": 0.30,
    "minimum_beacon_queries": 6
}
# Live alert cooldown (seconds)
ALERT_COOLDOWN = 60
def is_trusted_domain(parent_domain):

    parent_domain = parent_domain.lower()

    return any(
        parent_domain == domain
        or parent_domain.endswith("." + domain)
        for domain in TRUSTED_PARENT_DOMAINS
    )


# ============================================================
# Severity Ranking
# ============================================================

SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}


# ============================================================
# Live Detection State
# ============================================================

class DetectorState:
    """
    Stores running statistics for live monitoring.
    """

    def __init__(self):

        # Statistics

        self.total_queries = 0

        self.entropy_sum = 0.0

        self.domain_length_sum = 0

        self.subdomain_length_sum = 0

        self.label_count_sum = 0

        # Unique values

        self.unique_domains = set()

        self.unique_parent_domains = set()

        self.unique_subdomains = defaultdict(set)

        # Tracking

        self.frequency = Counter()
        # Rolling 60-second window
        self.frequency_windows = defaultdict(deque)
        # Last alert time for cooldown
        self.last_alert_time = {}

        self.timelines = defaultdict(list)

        self.highest_entropy_query = None

        self.longest_subdomain = None

        # Detection results

        self.suspicious_queries = []

        self.severity_counts = Counter()
    # ========================================================
    # State Updates
    # ========================================================

    def update_statistics(self, feature):

        self.total_queries += 1

        self.unique_domains.add(feature["domain"])

        self.unique_parent_domains.add(feature["parent_domain"])

        self.entropy_sum += feature["entropy"]

        self.domain_length_sum += feature["domain_length"]

        self.subdomain_length_sum += feature["subdomain_length"]

        self.label_count_sum += feature["dns_label_count"]


    def update_frequency(self, feature):

        parent = feature["parent_domain"]
        timestamp = feature["timestamp"]

        if timestamp is None:
            self.frequency[parent] += 1
            return

        window = self.frequency_windows[parent]

        window.append(timestamp)

        while window and (timestamp - window[0]) > 60:
            window.popleft()

        self.frequency[parent] = len(window)

    def update_unique_subdomains(self, feature):

        subdomain = feature["subdomain"]

        if subdomain:

            self.unique_subdomains[
                feature["parent_domain"]
            ].add(subdomain)


    def update_highest_entropy(self, feature):

        if (
            self.highest_entropy_query is None
            or
            feature["entropy"] >
            self.highest_entropy_query["entropy"]
        ):

            self.highest_entropy_query = feature


    def update_longest_subdomain(self, feature):

        if (
            self.longest_subdomain is None
            or
            feature["subdomain_length"] >
            self.longest_subdomain["subdomain_length"]
        ):

            self.longest_subdomain = feature


    def update_timeline(self, feature):

        timestamp = feature["timestamp"]

        if timestamp is None:
            return

        self.timelines[
            feature["parent_domain"]
        ].append(timestamp)


    # ========================================================
    # Running Averages
    # ========================================================

    @property
    def average_entropy(self):

        if self.total_queries == 0:
            return 0.0

        return round(
            self.entropy_sum /
            self.total_queries,
            3
        )


    @property
    def average_domain_length(self):

        if self.total_queries == 0:
            return 0

        return round(
            self.domain_length_sum /
            self.total_queries,
            2
        )


    @property
    def average_subdomain_length(self):

        if self.total_queries == 0:
            return 0

        return round(
            self.subdomain_length_sum /
            self.total_queries,
            2
        )


    @property
    def average_dns_labels(self):

        if self.total_queries == 0:
            return 0

        return round(
            self.label_count_sum /
            self.total_queries,
            2
        )


# ============================================================
# Basic Statistics
# ============================================================

def calculate_query_frequency(features):

    counter = Counter()

    for feature in features:
        counter[feature["parent_domain"]] += 1

    return dict(counter)


def get_top_domains(frequency_dict, top_n=10):

    return sorted(
        frequency_dict.items(),
        key=lambda x: x[1],
        reverse=True
    )[:top_n]


def count_unique_parent_domains(features):

    return len({
        feature["parent_domain"]
        for feature in features
    })


def count_unique_full_domains(features):

    return len({
        feature["domain"]
        for feature in features
    })


def calculate_average_entropy(features):

    if not features:
        return 0.0

    return round(
        mean(
            feature["entropy"]
            for feature in features
        ),
        3
    )


def get_highest_entropy_query(features):

    if not features:
        return None

    return max(
        features,
        key=lambda x: x["entropy"]
    )


def get_longest_subdomain(features):

    if not features:
        return None

    return max(
        features,
        key=lambda x: x["subdomain_length"]
    )
def calculate_average_domain_length(features):

    if not features:
        return 0

    return round(
        mean(
            feature["domain_length"]
            for feature in features
        ),
        2
    )


def calculate_average_subdomain_length(features):

    if not features:
        return 0

    return round(
        mean(
            feature["subdomain_length"]
            for feature in features
        ),
        2
    )


def calculate_average_dns_labels(features):

    if not features:
        return 0

    return round(
        mean(
            feature["dns_label_count"]
            for feature in features
        ),
        2
    )


# ============================================================
# Unique Subdomain Analysis
# ============================================================

def group_subdomains(features):

    grouped = defaultdict(set)

    for feature in features:

        subdomain = feature["subdomain"]

        if subdomain:

            grouped[
                feature["parent_domain"]
            ].add(subdomain)

    return grouped


def count_unique_subdomains(features):

    grouped = group_subdomains(features)

    return {
        parent: len(subdomains)
        for parent, subdomains in grouped.items()
    }


def find_unique_subdomain_candidates(features):

    candidates = []

    for parent, count in count_unique_subdomains(features).items():

        if count >= THRESHOLDS["unique_subdomains"]:

            candidates.append({

                "parent_domain": parent,

                "unique_subdomains": count

            })

    candidates.sort(

        key=lambda x: x["unique_subdomains"],

        reverse=True

    )

    return candidates


# ============================================================
# Entropy Analysis
# ============================================================

def find_high_entropy_queries(features):

    return [

        feature

        for feature in features

        if feature["entropy"]
        >= THRESHOLDS["entropy"]

    ]


def find_long_subdomains(features):

    return [

        feature

        for feature in features

        if feature["subdomain_length"]
        >= THRESHOLDS["subdomain_length"]

    ]
# ============================================================
# Frequency Analysis
# ============================================================

def find_high_frequency_domains(features):

    frequency = calculate_query_frequency(features)

    results = []

    for parent, count in frequency.items():

        if count >= THRESHOLDS["query_frequency"]:

            results.append({

                "parent_domain": parent,

                "query_count": count

            })

    results.sort(

        key=lambda x: x["query_count"],

        reverse=True

    )

    return results


# ============================================================
# Timeline Helpers
# ============================================================

def build_domain_timeline(features):

    timeline = defaultdict(list)

    for feature in features:

        timestamp = feature["timestamp"]

        if timestamp is not None:

            timeline[
                feature["parent_domain"]
            ].append(timestamp)

    for timestamps in timeline.values():

        timestamps.sort()

    return timeline


def calculate_intervals(timestamps):

    if len(timestamps) < 2:
        return []

    return [

        timestamps[i] - timestamps[i - 1]

        for i in range(1, len(timestamps))

    ]
# ============================================================
# Beacon Detection
# ============================================================

def calculate_interval_statistics(intervals):

    if not intervals:
        return None

    avg = mean(intervals)

    minimum = min(intervals)

    maximum = max(intervals)

    variance = 0 if avg == 0 else (maximum - minimum) / avg

    return {

        "average_interval": round(avg, 3),

        "minimum_interval": round(minimum, 3),

        "maximum_interval": round(maximum, 3),

        "variance_ratio": round(variance, 3)

    }


def detect_dns_beaconing(features):

    beaconing = []

    for parent, timestamps in build_domain_timeline(features).items():

        if len(timestamps) < THRESHOLDS["minimum_beacon_queries"]:
            continue

        intervals = calculate_intervals(timestamps)

        if len(intervals) < 2:
            continue

        stats = calculate_interval_statistics(intervals)

        if (
            stats
            and
            stats["variance_ratio"]
            <= THRESHOLDS["beacon_interval_variance"]
        ):

            beaconing.append({

                "parent_domain": parent,

                "query_count": len(timestamps),

                "average_interval": stats["average_interval"],

                "minimum_interval": stats["minimum_interval"],

                "maximum_interval": stats["maximum_interval"],

                "variance_ratio": stats["variance_ratio"]

            })

    beaconing.sort(

        key=lambda x: (

            x["variance_ratio"],

            -x["query_count"]

        )

    )

    return beaconing


# ============================================================
# Rule Evaluation
# ============================================================

def evaluate_entropy_rule(feature):

    return (
        feature["entropy"]
        >= THRESHOLDS["entropy"]
    )


def evaluate_length_rule(feature):

    return (
        feature["subdomain_length"]
        >= THRESHOLDS["subdomain_length"]
    )


def evaluate_frequency_rule(feature, frequency):

    return (
        frequency.get(
            feature["parent_domain"],
            0
        )
        >= THRESHOLDS["query_frequency"]
    )


def evaluate_unique_rule(feature, unique_counts):

    return (
        unique_counts.get(
            feature["parent_domain"],
            0
        )
        >= THRESHOLDS["unique_subdomains"]
    )


def evaluate_beacon_rule(feature, beacon_domains):

    return (
        feature["parent_domain"]
        in beacon_domains
    )
# ============================================================
# Shared Detection Helpers
# ============================================================

def build_indicators(
    entropy=False,
    length=False,
    frequency=False,
    unique=False,
    beacon=False
):

    indicators = []

    if entropy:
        indicators.append("High Entropy")

    if length:
        indicators.append("Long Subdomain")

    if frequency:
        indicators.append("High Query Frequency")

    if unique:
        indicators.append("Many Unique Subdomains")

    if beacon:
        indicators.append("Periodic DNS Beaconing")

    return indicators


def calculate_severity(
    trusted,
    entropy,
    length,
    frequency,
    unique,
    beacon,
    score
):

    # --------------------------------------------------------
    # Trusted infrastructure
    # --------------------------------------------------------

    if trusted:

      if entropy and unique:
        return "MEDIUM"

      if beacon:
        return "MEDIUM"

      if entropy:
        return "MEDIUM"

      return "LOW"

    # --------------------------------------------------------
    # High-confidence detections
    # --------------------------------------------------------

    if entropy and unique:
        return "CRITICAL"

    if entropy and length:
        return "HIGH"

    if beacon:
        return "HIGH"

    # --------------------------------------------------------
    # Medium-confidence detections
    # --------------------------------------------------------

    if entropy:
        return "MEDIUM"

    if length:
        return "MEDIUM"

    if unique:
        return "MEDIUM"

    # --------------------------------------------------------
    # Fallback
    # --------------------------------------------------------

    return "LOW"
# ============================================================
# Live Streaming Detection
# ============================================================

def process_live_query(feature, state):

    # --------------------------------------------------------
    # Update detector state
    # --------------------------------------------------------

    state.update_statistics(feature)
    state.update_frequency(feature)
    state.update_unique_subdomains(feature)
    state.update_highest_entropy(feature)
    state.update_longest_subdomain(feature)
    state.update_timeline(feature)

    timestamp = feature["timestamp"] or 0
    parent = feature["parent_domain"]

    # --------------------------------------------------------
    # Alert cooldown
    # --------------------------------------------------------

    last_alert = state.last_alert_time.get(parent)

    if (
        last_alert is not None
        and (timestamp - last_alert) < ALERT_COOLDOWN
    ):
        return None

    # --------------------------------------------------------
    # Evaluate rules
    # --------------------------------------------------------

    trusted = is_trusted_domain(parent)

    entropy = evaluate_entropy_rule(feature)

    length = evaluate_length_rule(feature)

    frequency = (
        state.frequency[parent]
        >= THRESHOLDS["query_frequency"]
    )

    unique = (
        len(state.unique_subdomains[parent])
        >= THRESHOLDS["unique_subdomains"]
    )

    # Placeholder until live beacon detection is added
    beacon = False

    # --------------------------------------------------------
    # Primary indicators
    # --------------------------------------------------------

    indicators = build_indicators(
        entropy=entropy,
        length=length,
        frequency=False,
        unique=unique,
        beacon=beacon
    )

    # No primary indicator -> no alert
    if not indicators:
        return None

    # Frequency is only a supporting indicator
    if frequency:
        indicators.append("High Query Frequency")

    # Count only primary indicators
    score = sum([
       entropy,
       length,
       unique,
       beacon
    ])
    # Require at least two primary indicators
    if score < 2 and not beacon:
       return None
    severity = calculate_severity(
        trusted,
        entropy,
        length,
        frequency,
        unique,
        beacon,
        score
    )

    result = {
        "domain": feature["domain"],
        "parent_domain": parent,
        "subdomain": feature["subdomain"],
        "timestamp": feature["timestamp"],
        "source_ip": feature["source_ip"],
        "entropy": feature["entropy"],
        "subdomain_length": feature["subdomain_length"],
        "domain_length": feature["domain_length"],
        "dns_label_count": feature["dns_label_count"],
        "frequency": state.frequency[parent],
        "unique_subdomains": len(state.unique_subdomains[parent]),
        "indicators": indicators,
        "score": score,
        "severity": severity,
        "is_trusted": trusted
    }

    state.suspicious_queries.append(result)
    state.severity_counts[severity] += 1
    state.last_alert_time[parent] = timestamp

    return result 
# ============================================================
# Rule-Based Detection
# ============================================================

def detect_suspicious_queries(features):

    frequency = calculate_query_frequency(features)

    unique_counts = count_unique_subdomains(features)

    beacon_results = detect_dns_beaconing(features)

    beacon_domains = {
        item["parent_domain"]
        for item in beacon_results
    }

    suspicious = []

    for feature in features:

        parent = feature["parent_domain"]

        trusted = is_trusted_domain(parent)

        entropy = evaluate_entropy_rule(feature)

        length = evaluate_length_rule(feature)

        freq = evaluate_frequency_rule(
            feature,
            frequency
        )

        unique = evaluate_unique_rule(
            feature,
            unique_counts
        )

        beacon = evaluate_beacon_rule(
            feature,
            beacon_domains
        )

        # ----------------------------------------------------
        # Primary indicators only
        # ----------------------------------------------------

        indicators = build_indicators(
            entropy=entropy,
            length=length,
            frequency=False,
            unique=unique,
            beacon=beacon
        )

        # No primary indicator -> ignore
        if not indicators:
            continue

        # Frequency is only a supporting indicator
        if freq:
            indicators.append("High Query Frequency")

        # Count only primary indicators
        score = sum([
           entropy,
           length,
           unique,
           beacon
        ])
        # Require at least two primary indicators
        if score < 2 and not beacon:
          continue
        severity = calculate_severity(
            trusted,
            entropy,
            length,
            freq,
            unique,
            beacon,
            score
        )

        suspicious.append({

            "domain": feature["domain"],
            "parent_domain": parent,
            "subdomain": feature["subdomain"],
            "timestamp": feature["timestamp"],
            "source_ip": feature["source_ip"],
            "entropy": feature["entropy"],
            "subdomain_length": feature["subdomain_length"],
            "domain_length": feature["domain_length"],
            "dns_label_count": feature["dns_label_count"],
            "frequency": frequency.get(parent, 0),
            "unique_subdomains": unique_counts.get(parent, 0),
            "indicators": indicators,
            "score": score,
            "severity": severity,
            "is_trusted": trusted

        })

    suspicious.sort(
        key=lambda x: (
            SEVERITY_RANK[x["severity"]],
            x["score"],
            x["entropy"]
        ),
        reverse=True
    )

    return suspicious
# ============================================================
# Risk Assessment
# ============================================================

def calculate_overall_risk(suspicious_queries):

    if not suspicious_queries:
        return "LOW"

    return max(
        suspicious_queries,
        key=lambda x: SEVERITY_RANK[x["severity"]]
    )["severity"]


def count_severity_levels(suspicious_queries):

    counts = Counter()

    for query in suspicious_queries:
        counts[query["severity"]] += 1

    return dict(counts)


# ============================================================
# Threat Summary
# ============================================================

def generate_threat_summary(features, suspicious_queries):

    frequency = calculate_query_frequency(features)

    unique_parent_domains = count_unique_parent_domains(features)

    unique_domains = count_unique_full_domains(features)

    average_entropy = calculate_average_entropy(features)

    average_domain_length = calculate_average_domain_length(features)

    average_subdomain_length = calculate_average_subdomain_length(features)

    average_dns_labels = calculate_average_dns_labels(features)

    highest_entropy_query = get_highest_entropy_query(features)

    longest_subdomain = get_longest_subdomain(features)

    top_domains = get_top_domains(
        frequency,
        top_n=10
    )

    return {

        "overall_risk":
            calculate_overall_risk(
                suspicious_queries
            ),

        "total_queries":
            len(features),

        "suspicious_queries":
            len(suspicious_queries),

        "unique_parent_domains":
            unique_parent_domains,

        "unique_domains":
            unique_domains,

        "average_entropy":
            average_entropy,

        "average_domain_length":
            average_domain_length,

        "average_subdomain_length":
            average_subdomain_length,

        "average_dns_labels":
            average_dns_labels,

        "highest_entropy_query":
            highest_entropy_query,

        "longest_subdomain":
            longest_subdomain,

        "top_domains":
            top_domains

    }
# ============================================================
# Reporting
# ============================================================

def get_queries_by_severity(
    suspicious_queries,
    severity
):

    return [

        query

        for query in suspicious_queries

        if query["severity"] == severity

    ]


def get_top_entropy_queries(
    features,
    limit=10
):

    return sorted(

        features,

        key=lambda x: x["entropy"],

        reverse=True

    )[:limit]


def get_top_longest_subdomains(
    features,
    limit=10
):

    return sorted(

        features,

        key=lambda x: x["subdomain_length"],

        reverse=True

    )[:limit]


def get_top_suspicious_queries(
    suspicious_queries,
    limit=10
):

    return sorted(

        suspicious_queries,

        key=lambda x: (

            SEVERITY_RANK[x["severity"]],

            x["score"],

            x["entropy"]

        ),

        reverse=True

    )[:limit]


def get_beaconing_domains(features):

    return detect_dns_beaconing(features)
# ============================================================
# Analysis Pipeline
# ============================================================

def analyze_dns_traffic(features):

    frequency = calculate_query_frequency(features)

    unique_subdomains = count_unique_subdomains(features)

    beaconing = detect_dns_beaconing(features)

    average_entropy = calculate_average_entropy(features)

    average_domain_length = calculate_average_domain_length(features)

    average_subdomain_length = calculate_average_subdomain_length(features)

    average_dns_labels = calculate_average_dns_labels(features)

    unique_domains = count_unique_full_domains(features)

    unique_parent_domains = count_unique_parent_domains(features)

    suspicious = detect_suspicious_queries(features)

    return {

        "summary":
            generate_threat_summary(
                features,
                suspicious
            ),

        "statistics": {

            "total_queries":
                len(features),

            "unique_domains":
                unique_domains,

            "unique_parent_domains":
                unique_parent_domains,

            "average_entropy":
                average_entropy,

            "average_domain_length":
                average_domain_length,

            "average_subdomain_length":
                average_subdomain_length,

            "average_dns_labels":
                average_dns_labels

        },

        "query_frequency":
            frequency,

        "unique_subdomains":
            unique_subdomains,

        "beaconing":
            beaconing,

        "high_entropy_queries":
            find_high_entropy_queries(features),

        "long_subdomains":
            find_long_subdomains(features),

        "high_frequency_domains":
            find_high_frequency_domains(features),

        "unique_subdomain_candidates":
            find_unique_subdomain_candidates(features),

        "suspicious_queries":
            suspicious,

        "severity_counts":
            count_severity_levels(
                suspicious
            ),

        "critical_queries":
            get_queries_by_severity(
                suspicious,
                "CRITICAL"
            ),

        "high_queries":
            get_queries_by_severity(
                suspicious,
                "HIGH"
            ),

        "medium_queries":
            get_queries_by_severity(
                suspicious,
                "MEDIUM"
            ),

        "low_queries":
            get_queries_by_severity(
                suspicious,
                "LOW"
            ),

        "top_entropy_queries":
            get_top_entropy_queries(features),

        "top_longest_subdomains":
            get_top_longest_subdomains(features),

        "top_suspicious_queries":
            get_top_suspicious_queries(
                suspicious
            )

    }
# ============================================================
# Public API
# ============================================================

__all__ = [

    "THRESHOLDS",
    "SEVERITY_RANK",
    "DetectorState",
    "process_live_query",

    "calculate_query_frequency",
    "get_top_domains",

    "count_unique_parent_domains",
    "count_unique_full_domains",
    "count_unique_subdomains",

    "calculate_average_entropy",
    "calculate_average_domain_length",
    "calculate_average_subdomain_length",
    "calculate_average_dns_labels",

    "get_highest_entropy_query",
    "get_longest_subdomain",

    "find_high_entropy_queries",
    "find_long_subdomains",
    "find_high_frequency_domains",
    "find_unique_subdomain_candidates",

    "detect_dns_beaconing",
    "detect_suspicious_queries",

    "calculate_overall_risk",
    "count_severity_levels",

    "generate_threat_summary",

    "get_beaconing_domains",
    "get_top_entropy_queries",
    "get_top_longest_subdomains",
    "get_top_suspicious_queries",

    "analyze_dns_traffic"
]
