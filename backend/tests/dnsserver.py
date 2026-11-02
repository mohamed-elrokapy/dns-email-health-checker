"""A tiny authoritative DNS server on localhost, used to test the real resolver adapter."""

from __future__ import annotations

import socket
import threading

import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset


def _fqdn(name: str) -> str:
    return name.lower().rstrip(".") + "."


class LocalDnsServer:
    """Answers from an in-memory zone. Names that do not exist get NXDOMAIN."""

    def __init__(
        self,
        records: list[tuple[str, str, str]],
        servfail: set[str] | None = None,
        port: int = 0,
    ):
        self._rrsets: dict[tuple[str, str], list[str]] = {}
        self._names: set[str] = set()
        for name, rdtype, text in records:
            self._rrsets.setdefault((_fqdn(name), rdtype), []).append(text)
            self._names.add(_fqdn(name))
        self._servfail = {_fqdn(n) for n in (servfail or set())}
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", port))
        self._sock.settimeout(0.2)
        self.port: int = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> LocalDnsServer:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self._sock.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(4096)
            except TimeoutError:
                continue
            except OSError:
                return
            try:
                query = dns.message.from_wire(data)
            except Exception:  # noqa: BLE001 - ignore malformed packets in a test server
                continue
            self._sock.sendto(self._answer(query).to_wire(), addr)

    def _answer(self, query: dns.message.Message) -> dns.message.Message:
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA
        question = query.question[0]
        name = question.name.to_text().lower()
        rdtype = dns.rdatatype.to_text(question.rdtype)
        if name in self._servfail:
            response.set_rcode(dns.rcode.SERVFAIL)
            return response
        texts = self._rrsets.get((name, rdtype))
        if texts:
            response.answer.append(dns.rrset.from_text_list(name, 300, "IN", rdtype, texts))
        elif name not in self._names:
            response.set_rcode(dns.rcode.NXDOMAIN)
        return response


def txt_rdata(value: str) -> str:
    """Quote a TXT value, splitting it into 255-character strings like real DNS does."""
    chunks = [value[i : i + 255] for i in range(0, len(value), 255)] or [""]
    return " ".join(f'"{chunk}"' for chunk in chunks)
