"""DKIM check (RFC 6376): look up selector records and validate the published keys.

DKIM selectors are chosen by the sender and cannot be listed through DNS. The check
probes a short list of common selectors plus any the caller supplies.
"""

from __future__ import annotations

import base64
import binascii
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

from app.models import CheckResult, Status
from app.resolver import DNSLookupError, Resolver

CHECK_ID = "dkim"
TITLE = "DKIM"
COMMON_SELECTORS = (
    "default", "google", "selector1", "selector2", "k1", "s1", "s2", "mail", "dkim", "smtp",
)  # fmt: skip
MIN_RSA_BITS = 1024
RECOMMENDED_RSA_BITS = 2048


@dataclass
class _Finding:
    selector: str
    status: Status
    message: str
    record: str | None = None


def _parse_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        key, sep, value = part.strip().partition("=")
        if sep and key.strip():
            tags[key.strip().lower()] = value.strip()
    return tags


def _evaluate(selector: str, record: str) -> _Finding:
    tags = _parse_tags(record)
    key_type = tags.get("k", "rsa").lower()
    encoded = "".join(tags.get("p", "").split())
    if not encoded:
        return _Finding(selector, Status.FAIL, "The key is empty, so this key was revoked.", record)
    try:
        raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True)
    except (binascii.Error, ValueError):
        return _Finding(selector, Status.FAIL, "The p= value is not valid base64.", record)

    if key_type == "ed25519":
        if len(raw) == 32:
            return _Finding(selector, Status.PASS, "Ed25519 key.", record)
        return _Finding(selector, Status.FAIL, "Ed25519 key has the wrong length.", record)

    try:
        key = load_der_public_key(raw)
    except ValueError:
        return _Finding(selector, Status.FAIL, "The p= value is not a valid public key.", record)
    if not isinstance(key, rsa.RSAPublicKey):
        return _Finding(selector, Status.FAIL, "The key is not an RSA key.", record)
    if key.key_size < MIN_RSA_BITS:
        return _Finding(selector, Status.FAIL, f"RSA key is only {key.key_size} bits.", record)
    if key.key_size < RECOMMENDED_RSA_BITS:
        return _Finding(
            selector,
            Status.WARN,
            f"RSA key is {key.key_size} bits. Use {RECOMMENDED_RSA_BITS} bits.",
            record,
        )
    return _Finding(selector, Status.PASS, f"RSA {key.key_size}-bit key.", record)


def _lookup(resolver: Resolver, domain: str, selector: str) -> _Finding | None:
    try:
        texts = resolver.txt(f"{selector}._domainkey.{domain}")
    except DNSLookupError as exc:
        return _Finding(selector, Status.WARN, f"Lookup failed: {exc}")
    records = [t for t in texts if "p=" in t.replace(" ", "").lower()]
    if not records:
        return None
    return _evaluate(selector, records[0])


def check_dkim(resolver: Resolver, domain: str, selectors: list[str] | None = None) -> CheckResult:
    requested = list(selectors or [])
    probe = requested + [s for s in COMMON_SELECTORS if s not in requested]

    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(lambda s: _lookup(resolver, domain, s), probe))
    findings = [f for f in results if f is not None]

    if not findings:
        if requested:
            return CheckResult(
                id=CHECK_ID,
                title=TITLE,
                status=Status.FAIL,
                summary="No DKIM record found for the selectors you provided.",
                details=[
                    "Selectors tried: " + ", ".join(requested),
                    "Check the selector name in the DKIM-Signature header of a sent message.",
                ],
            )
        return CheckResult(
            id=CHECK_ID,
            title=TITLE,
            status=Status.WARN,
            summary="No DKIM record found for the common selectors.",
            details=[
                "DKIM selectors are arbitrary, so this does not prove DKIM is missing.",
                "Add the selector from a sent message's DKIM-Signature header to check it.",
            ],
        )

    details = [f"{f.selector}: {f.message}" for f in findings]
    if any(f.status is Status.FAIL for f in findings):
        status = Status.FAIL
        summary = "A DKIM record was found but has a problem."
    elif any(f.status is Status.WARN for f in findings):
        status = Status.WARN
        summary = "DKIM is published, with warnings."
    else:
        status = Status.PASS
        summary = f"DKIM is published for {len(findings)} selector(s)."
    return CheckResult(
        id=CHECK_ID,
        title=TITLE,
        status=status,
        summary=summary,
        details=details,
        records=[f.record for f in findings if f.record],
    )
