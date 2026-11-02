"""MX check: can the domain receive mail, and do its mail hosts resolve?"""

from __future__ import annotations

from app.models import CheckResult, Status
from app.resolver import Resolver

CHECK_ID = "mx"
TITLE = "MX records"


def check_mx(resolver: Resolver, domain: str) -> CheckResult:
    records = sorted(resolver.mx(domain))
    shown = [f"{preference} {host or '.'}" for preference, host in records]

    if not records:
        if resolver.addresses(domain):
            return CheckResult(
                id=CHECK_ID,
                title=TITLE,
                status=Status.WARN,
                summary="No MX record. Mail would fall back to the domain's A/AAAA record.",
                details=[
                    "Without an MX record, senders use the domain's own address (RFC 5321). "
                    "Publish an explicit MX record so routing is intentional."
                ],
            )
        return CheckResult(
            id=CHECK_ID,
            title=TITLE,
            status=Status.FAIL,
            summary="No MX record and no address record. This domain cannot receive email.",
            details=["Add MX records that point to your mail provider."],
        )

    if len(records) == 1 and records[0][1] == "":
        return CheckResult(
            id=CHECK_ID,
            title=TITLE,
            status=Status.INFO,
            summary="The domain publishes a null MX and states that it accepts no email.",
            records=shown,
        )

    details: list[str] = []
    unresolved = [host for _, host in records if host and not resolver.addresses(host)]
    if unresolved:
        details.append(
            "These mail hosts do not resolve to an A/AAAA address: " + ", ".join(unresolved)
        )
    if len(records) == 1:
        details.append("Only one MX host is published, so there is no failover.")

    if len(unresolved) == len([r for r in records if r[1]]):
        status = Status.FAIL
        summary = "None of the MX hosts resolve, so mail cannot be delivered."
    elif unresolved:
        status = Status.WARN
        summary = f"{len(records)} MX records, but some hosts do not resolve."
    else:
        status = Status.PASS
        summary = f"{len(records)} MX record(s), all hosts resolve."
    return CheckResult(
        id=CHECK_ID, title=TITLE, status=status, summary=summary, details=details, records=shown
    )
