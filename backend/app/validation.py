"""Input validation for domain names and DKIM selectors.

The service only performs DNS lookups, but user input still ends up in DNS
queries, so it is normalised and restricted before use.
"""

from __future__ import annotations

import ipaddress
import re

import idna

MAX_SELECTORS = 10
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_SELECTOR = re.compile(r"^[a-z0-9]([a-z0-9._-]{0,61}[a-z0-9])?$")
_BLOCKED_SUFFIXES = (".local", ".localhost", ".internal", ".invalid", ".arpa", ".onion")


class InvalidInput(ValueError):
    """Raised when user input is not a usable domain or selector."""


def normalize_domain(raw: str) -> str:
    """Return the lower-case ASCII (punycode) form of a domain, or raise InvalidInput."""
    value = raw.strip().lower().rstrip(".")
    if not value:
        raise InvalidInput("Domain is empty.")
    if len(value) > 253:
        raise InvalidInput("Domain is longer than 253 characters.")

    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise InvalidInput("IP addresses are not accepted, enter a domain name.")

    try:
        ascii_name = idna.encode(value, uts46=True).decode("ascii")
    except (idna.IDNAError, UnicodeError) as exc:
        raise InvalidInput(f"Invalid domain name: {exc}") from exc

    labels = ascii_name.split(".")
    if len(labels) < 2:
        raise InvalidInput("Enter a full domain such as example.com.")
    if any(not _LABEL.match(label) for label in labels):
        raise InvalidInput("Domain contains invalid characters.")
    if labels[-1].isdigit():
        raise InvalidInput("The top-level domain cannot be numeric.")
    if ascii_name.endswith(_BLOCKED_SUFFIXES):
        raise InvalidInput("This domain suffix is not allowed.")
    return ascii_name


def normalize_selectors(raw: list[str]) -> list[str]:
    """Lower-case, validate and de-duplicate DKIM selectors, keeping their order."""
    seen: list[str] = []
    for item in raw:
        selector = item.strip().lower()
        if not _SELECTOR.match(selector):
            raise InvalidInput(f"Invalid DKIM selector: {item!r}.")
        if selector not in seen:
            seen.append(selector)
    if len(seen) > MAX_SELECTORS:
        raise InvalidInput(f"At most {MAX_SELECTORS} DKIM selectors are allowed.")
    return seen
