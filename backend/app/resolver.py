"""DNS access behind a small interface so the checks can be tested without a network."""

from __future__ import annotations

from typing import Protocol

import dns.exception
import dns.resolver


class DNSLookupError(Exception):
    """A DNS query failed in a way that is not 'the record does not exist'."""


class Resolver(Protocol):
    def txt(self, name: str) -> list[str]:
        """TXT strings for a name, each record's chunks joined. Empty if none exist."""

    def mx(self, name: str) -> list[tuple[int, str]]:
        """(preference, host) pairs. A null MX is returned as host ''."""

    def addresses(self, name: str) -> list[str]:
        """A and AAAA addresses for a name. Empty if none exist."""

    def domain_exists(self, name: str) -> bool:
        """False only when the name does not exist at all (NXDOMAIN)."""


class DnsPythonResolver:
    """Production resolver built on dnspython with strict timeouts."""

    def __init__(
        self,
        timeout: float = 3.0,
        nameservers: list[str] | None = None,
        port: int = 53,
    ) -> None:
        self._resolver = dns.resolver.Resolver(configure=True)
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout
        if nameservers:
            self._resolver.nameservers = nameservers
        self._resolver.port = port

    def _resolve(self, name: str, rdtype: str) -> list:
        try:
            answer = self._resolver.resolve(name, rdtype, raise_on_no_answer=False)
            return list(answer)
        except dns.resolver.NXDOMAIN:
            return []
        except dns.exception.Timeout as exc:
            raise DNSLookupError(f"DNS query for {name} ({rdtype}) timed out.") from exc
        except dns.exception.DNSException as exc:
            raise DNSLookupError(
                f"DNS query for {name} ({rdtype}) failed: {type(exc).__name__}."
            ) from exc

    def txt(self, name: str) -> list[str]:
        return [
            b"".join(record.strings).decode("utf-8", "replace")
            for record in self._resolve(name, "TXT")
        ]

    def mx(self, name: str) -> list[tuple[int, str]]:
        return [
            (record.preference, record.exchange.to_text().rstrip("."))
            for record in self._resolve(name, "MX")
        ]

    def addresses(self, name: str) -> list[str]:
        found: list[str] = []
        for rdtype in ("A", "AAAA"):
            found.extend(record.address for record in self._resolve(name, rdtype))
        return found

    def domain_exists(self, name: str) -> bool:
        try:
            self._resolver.resolve(name, "SOA", raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return False
        except dns.exception.Timeout as exc:
            raise DNSLookupError(f"DNS query for {name} timed out.") from exc
        except dns.exception.DNSException as exc:
            raise DNSLookupError(f"DNS query for {name} failed: {type(exc).__name__}.") from exc
        return True
