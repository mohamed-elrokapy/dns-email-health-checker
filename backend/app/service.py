"""Runs all checks for a domain and rolls the results up into one verdict."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from app.checks import dkim, dmarc, mx, spf
from app.models import CheckResponse, CheckResult, Status
from app.resolver import DNSLookupError, Resolver


class DomainNotFound(Exception):
    """The domain does not exist in DNS (NXDOMAIN)."""


_RANK = {Status.INFO: 0, Status.PASS: 1, Status.WARN: 2, Status.FAIL: 3}


def _safe(check_id: str, title: str, run: Callable[[], CheckResult]) -> CheckResult:
    try:
        return run()
    except DNSLookupError as exc:
        return CheckResult(
            id=check_id,
            title=title,
            status=Status.WARN,
            summary="This check could not be completed.",
            details=[str(exc)],
        )


def overall_status(results: list[CheckResult]) -> Status:
    scored = [r.status for r in results if r.status is not Status.INFO]
    if not scored:
        return Status.INFO
    return max(scored, key=_RANK.__getitem__)


def run_checks(resolver: Resolver, domain: str, selectors: list[str]) -> CheckResponse:
    """Raises DomainNotFound for NXDOMAIN and DNSLookupError if DNS itself is unreachable."""
    if not resolver.domain_exists(domain):
        raise DomainNotFound(domain)

    jobs: list[tuple[str, str, Callable[[], CheckResult]]] = [
        (mx.CHECK_ID, mx.TITLE, lambda: mx.check_mx(resolver, domain)),
        (spf.CHECK_ID, spf.TITLE, lambda: spf.check_spf(resolver, domain)),
        (dkim.CHECK_ID, dkim.TITLE, lambda: dkim.check_dkim(resolver, domain, selectors)),
        (dmarc.CHECK_ID, dmarc.TITLE, lambda: dmarc.check_dmarc(resolver, domain)),
    ]
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = [pool.submit(_safe, cid, title, run) for cid, title, run in jobs]
        results = [future.result() for future in futures]
    return CheckResponse(domain=domain, overall=overall_status(results), checks=results)
