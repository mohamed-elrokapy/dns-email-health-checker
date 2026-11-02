"""SPF check (RFC 7208): record presence, DNS lookup budget and the final policy."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.models import CheckResult, Status
from app.resolver import Resolver

CHECK_ID = "spf"
TITLE = "SPF"
MAX_LOOKUPS = 10
WARN_LOOKUPS = 8
MAX_DEPTH = 10
_SPF_PREFIX = re.compile(r"^v=spf1(\s|$)", re.IGNORECASE)
_QUALIFIERS = "+-~?"


@dataclass
class _Walk:
    lookups: int = 0
    seen: set[str] = field(default_factory=set)
    problems: list[tuple[Status, str]] = field(default_factory=list)


def _spf_records(resolver: Resolver, domain: str) -> list[str]:
    return [t.strip() for t in resolver.txt(domain) if _SPF_PREFIX.match(t.strip())]


def _follow(resolver: Resolver, target: str, walk: _Walk, depth: int) -> None:
    target = target.strip().lower().rstrip(".")
    if not target:
        walk.problems.append((Status.FAIL, "An include or redirect has no domain."))
        return
    if depth >= MAX_DEPTH:
        walk.problems.append((Status.FAIL, f"Nested includes are deeper than {MAX_DEPTH} levels."))
        return
    if target in walk.seen:
        walk.problems.append((Status.FAIL, f"SPF includes loop back to {target}."))
        return
    walk.seen.add(target)
    records = _spf_records(resolver, target)
    if not records:
        walk.problems.append(
            (Status.FAIL, f"{target} is referenced but publishes no SPF record (permerror).")
        )
        return
    if len(records) > 1:
        walk.problems.append((Status.FAIL, f"{target} publishes more than one SPF record."))
        return
    _walk_record(resolver, records[0], walk, depth + 1)


def _walk_record(resolver: Resolver, record: str, walk: _Walk, depth: int) -> None:
    for term in record.split()[1:]:
        head = term.split(":", 1)[0]
        if "=" in head or ("=" in term and ":" not in term):
            key, _, value = term.partition("=")
            if key.lower() == "redirect":
                walk.lookups += 1
                _follow(resolver, value, walk, depth)
            continue
        body = term.lstrip(_QUALIFIERS)
        mechanism, _, argument = body.partition(":")
        mechanism = mechanism.lower().split("/")[0]
        if mechanism in ("a", "mx", "exists"):
            walk.lookups += 1
        elif mechanism == "ptr":
            walk.lookups += 1
            walk.problems.append((Status.WARN, "The 'ptr' mechanism is deprecated (RFC 7208)."))
        elif mechanism == "include":
            walk.lookups += 1
            _follow(resolver, argument, walk, depth)


def _all_qualifier(record: str) -> str | None:
    qualifier = None
    for term in record.split()[1:]:
        if term.lstrip(_QUALIFIERS).lower() == "all":
            qualifier = term[0] if term[0] in _QUALIFIERS else "+"
    return qualifier


def _has_redirect(record: str) -> bool:
    return any(t.lower().startswith("redirect=") for t in record.split()[1:])


def check_spf(resolver: Resolver, domain: str) -> CheckResult:
    records = _spf_records(resolver, domain)
    if not records:
        return CheckResult(
            id=CHECK_ID,
            title=TITLE,
            status=Status.FAIL,
            summary="No SPF record found.",
            details=[
                "Publish one TXT record that starts with v=spf1 and lists the servers "
                "allowed to send mail for this domain."
            ],
        )
    if len(records) > 1:
        return CheckResult(
            id=CHECK_ID,
            title=TITLE,
            status=Status.FAIL,
            summary=f"{len(records)} SPF records found. Exactly one is allowed.",
            details=["Receivers return a permanent error when a domain has several SPF records."],
            records=records,
        )

    record = records[0]
    walk = _Walk(seen={domain})
    _walk_record(resolver, record, walk, 0)

    problems = list(walk.problems)
    if walk.lookups > MAX_LOOKUPS:
        problems.append(
            (
                Status.FAIL,
                f"{walk.lookups} DNS lookups are needed. The limit is {MAX_LOOKUPS}, "
                "above it receivers return a permanent error.",
            )
        )
    elif walk.lookups >= WARN_LOOKUPS:
        problems.append(
            (Status.WARN, f"{walk.lookups} of {MAX_LOOKUPS} allowed DNS lookups are used.")
        )

    qualifier = _all_qualifier(record)
    if qualifier is None and not _has_redirect(record):
        problems.append((Status.WARN, "The record has no 'all' mechanism, so the policy is open."))
        policy = "no 'all' mechanism"
    else:
        policy = {
            "-": "-all (reject unlisted senders)",
            "~": "~all (soft fail unlisted senders)",
            "?": "?all (neutral)",
            "+": "+all (allow everyone)",
            None: "redirect",
        }[qualifier]
        if qualifier == "+":
            problems.append(
                (Status.FAIL, "+all allows any server to send as this domain. Use -all or ~all.")
            )
        elif qualifier == "?":
            problems.append((Status.WARN, "?all gives no protection. Use -all or ~all."))

    details = [text for _, text in problems]
    if qualifier == "~":
        details.append("~all is acceptable. Consider -all once DMARC is enforced.")

    if any(level is Status.FAIL for level, _ in problems):
        status = Status.FAIL
    elif any(level is Status.WARN for level, _ in problems):
        status = Status.WARN
    else:
        status = Status.PASS
    return CheckResult(
        id=CHECK_ID,
        title=TITLE,
        status=status,
        summary=f"SPF record found. {walk.lookups}/{MAX_LOOKUPS} DNS lookups. Policy: {policy}.",
        details=details,
        records=[record],
    )
