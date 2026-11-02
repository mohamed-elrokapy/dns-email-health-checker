"""Shared test helpers: an in-memory resolver and DKIM key builders."""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.resolver import DNSLookupError


class FakeResolver:
    """Dictionary-backed resolver implementing the app.resolver.Resolver protocol."""

    def __init__(
        self,
        txt: dict[str, list[str]] | None = None,
        mx: dict[str, list[tuple[int, str]]] | None = None,
        addresses: dict[str, list[str]] | None = None,
        existing: bool = True,
        failing: set[str] | None = None,
    ) -> None:
        self._txt = txt or {}
        self._mx = mx or {}
        self._addresses = addresses or {}
        self._existing = existing
        self._failing = failing or set()

    def _check(self, name: str) -> None:
        if name in self._failing:
            raise DNSLookupError(f"simulated failure for {name}")

    def txt(self, name: str) -> list[str]:
        self._check(name)
        return list(self._txt.get(name, []))

    def mx(self, name: str) -> list[tuple[int, str]]:
        self._check(name)
        return list(self._mx.get(name, []))

    def addresses(self, name: str) -> list[str]:
        self._check(name)
        return list(self._addresses.get(name, []))

    def domain_exists(self, name: str) -> bool:
        self._check(name)
        return self._existing


def dkim_record(bits: int = 2048) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return "v=DKIM1; k=rsa; p=" + base64.b64encode(der).decode()


@pytest.fixture(scope="session")
def rsa2048_record() -> str:
    return dkim_record(2048)


@pytest.fixture(scope="session")
def rsa1024_record() -> str:
    return dkim_record(1024)
