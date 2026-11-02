"""DMARC check (RFC 7489): record presence, policy strength and reporting."""

from __future__ import annotations

from app.models import CheckResult, Status
from app.resolver import Resolver

CHECK_ID = "dmarc"
TITLE = "DMARC"
_POLICIES = {"none", "quarantine", "reject"}


def _parse_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        key, sep, value = part.strip().partition("=")
        if sep and key.strip():
            tags[key.strip().lower()] = value.strip()
    return tags


def check_dmarc(resolver: Resolver, domain: str) -> CheckResult:
    records = [
        t.strip()
        for t in resolver.txt(f"_dmarc.{domain}")
        if t.strip().lower().replace(" ", "").startswith("v=dmarc1")
    ]
    if not records:
        return CheckResult(
            id=CHECK_ID,
            title=TITLE,
            status=Status.FAIL,
            summary="No DMARC record found.",
            details=[
                f"Publish a TXT record at _dmarc.{domain}, for example "
                "'v=DMARC1; p=none; rua=mailto:dmarc@" + domain + "' to start collecting reports.",
                "Subdomains without their own record fall back to the organisational domain.",
            ],
        )
    if len(records) > 1:
        return CheckResult(
            id=CHECK_ID,
            title=TITLE,
            status=Status.FAIL,
            summary=f"{len(records)} DMARC records found. Exactly one is allowed.",
            details=["Receivers ignore DMARC when more than one record is published."],
            records=records,
        )

    record = records[0]
    tags = _parse_tags(record)
    policy = tags.get("p", "").lower()
    details: list[str] = []

    if policy not in _POLICIES:
        return CheckResult(
            id=CHECK_ID,
            title=TITLE,
            status=Status.FAIL,
            summary="The DMARC record has a missing or invalid 'p' policy.",
            details=["The p tag must be none, quarantine or reject."],
            records=[record],
        )

    if policy == "none":
        status = Status.WARN
        summary = "DMARC is published in monitoring mode (p=none). Nothing is blocked."
        details.append("Move to p=quarantine, then p=reject, after reviewing the reports.")
    else:
        status = Status.PASS
        summary = f"DMARC is enforced with p={policy}."

    pct = tags.get("pct")
    if pct is not None:
        try:
            if int(pct) < 100:
                status = Status.WARN if status is Status.PASS else status
                details.append(f"pct={pct}, so the policy only applies to part of the mail.")
        except ValueError:
            details.append(f"pct={pct!r} is not a number.")
            status = Status.WARN if status is Status.PASS else status

    if "rua" not in tags:
        details.append("No rua tag, so you will not receive aggregate reports.")
    if "sp" in tags and tags["sp"].lower() not in _POLICIES:
        details.append(f"sp={tags['sp']!r} is not a valid subdomain policy.")
        status = Status.WARN if status is Status.PASS else status

    return CheckResult(
        id=CHECK_ID,
        title=TITLE,
        status=status,
        summary=summary,
        details=details,
        records=[record],
    )
