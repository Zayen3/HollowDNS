"""
Trusted domains and ignored DNS patterns.
"""

TRUSTED_PARENT_DOMAINS = {

    # Google
    "google.com",
    "googleapis.com",
    "googleusercontent.com",
    "googlevideo.com",
    "gstatic.com",

    # Microsoft
    "microsoft.com",
    "windowsupdate.com",
    "office.com",
    "live.com",
    "bing.com",
    "msn.com",

    # Cloudflare
    "cloudflare.com",
    "cloudflare-dns.com",

    # AWS
    "amazonaws.com",
    "amazon.com",

    # GitHub
    "github.com",
    "githubusercontent.com",

    # Apple
    "apple.com",
    "icloud.com"
}


IGNORED_SUFFIXES = {
    ".local",
    ".localhost",
    ".home.arpa"
}


IGNORED_PREFIXES = {
    "_tcp",
    "_udp",
    "_ldap",
    "_kerberos",
    "_googlecast"
}