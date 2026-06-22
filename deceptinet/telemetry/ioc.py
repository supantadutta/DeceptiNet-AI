"""IOC extractor (Phase 4, spec §4).

Regex-extracts indicators of compromise from captured interaction text (commands,
responses) plus the credentials table: IPv4/IPv6, URLs, domains, file hashes,
crypto-wallet addresses, downloaded-payload references, and credentials tried.

Operates only on already-stored data — no network, no fabrication. Extraction is
necessarily noisy (e.g. domain-like tokens); we bias toward recall and dedupe,
and note the noise in LIMITATIONS.md. Domains are taken from URLs plus a curated
common-TLD allowlist to cut obvious false positives.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

_CMD_TYPES = {"command", "exec_command", "http_request", "mysql_query", "mysql_command"}

_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_IPV6 = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b")
_URL = re.compile(r"\b(?:https?|ftp|tftp)://[^\s\"'<>\\)]+", re.I)
_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_BTC = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})\b", re.I)

# TLDs we accept for *standalone* domain extraction (URL hosts bypass this).
_COMMON_TLDS = {
    "com", "net", "org", "io", "ru", "cn", "info", "xyz", "top", "biz", "co",
    "us", "uk", "de", "br", "in", "ir", "pw", "cc", "su", "online", "site",
    "club", "shop", "tk", "ml", "ga", "cf", "gq", "live", "dev", "app",
}
# Local/loopback hosts that are not useful as IOCs.
_NOISE_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


def _texts(events) -> list[str]:
    out: list[str] = []
    for e in events:
        if e.command:
            out.append(e.command)
        if e.event_type in _CMD_TYPES and e.response:
            out.append(e.response)
    return out


def extract_iocs(events, credentials) -> dict[str, list[str]]:
    """Return a mapping of ioc_type -> sorted unique values."""
    found: dict[str, set[str]] = {
        k: set() for k in (
            "ipv4", "ipv6", "url", "domain", "md5", "sha1", "sha256",
            "btc_wallet", "eth_wallet", "payload_url", "credential",
        )
    }
    blob = "\n".join(_texts(events))

    for m in _IPV4.findall(blob):
        if m not in _NOISE_HOSTS:
            found["ipv4"].add(m)
    found["ipv6"].update(_IPV6.findall(blob))
    # Hashes: match longest first so a sha256 isn't also logged as md5/sha1.
    found["sha256"].update(_SHA256.findall(blob))
    found["sha1"].update(x for x in _SHA1.findall(blob))
    found["md5"].update(x for x in _MD5.findall(blob))
    found["eth_wallet"].update(_ETH.findall(blob))
    for w in _BTC.findall(blob):
        if not w.startswith("0x"):
            found["btc_wallet"].add(w)

    for url in _URL.findall(blob):
        found["url"].add(url)
        host = (urlparse(url).hostname or "").lower()
        if host and host not in _NOISE_HOSTS and not _IPV4.fullmatch(host):
            found["domain"].add(host)

    # Standalone domains (TLD allowlist to limit noise).
    for m in _DOMAIN.finditer(blob):
        host = m.group(0).lower()
        tld = m.group(1).lower()
        if tld in _COMMON_TLDS and host not in _NOISE_HOSTS:
            found["domain"].add(host)

    # Payload references: URLs fetched via download tools.
    for txt in _texts(events):
        if re.search(r"\b(wget|curl|tftp|ftpget|scp|fetch)\b", txt, re.I):
            for url in _URL.findall(txt):
                found["payload_url"].add(url)

    for c in credentials:
        pw = "" if c.password is None else c.password
        found["credential"].add(f"{c.username}:{pw}")

    # Avoid double-counting hashes: a 32-hex that is part of a 40/64 match set is
    # already captured separately; we keep them as-is (regexes use word bounds).
    return {k: sorted(v) for k, v in found.items() if v}
