"""HTTP API. Create the app with create_app() so tests can inject fakes."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

from app.models import CheckRequest, CheckResponse
from app.ratelimit import SlidingWindowLimiter
from app.resolver import DNSLookupError, DnsPythonResolver, Resolver
from app.service import DomainNotFound, run_checks
from app.validation import InvalidInput, normalize_domain, normalize_selectors

logger = logging.getLogger("dns_email_health")


@dataclass(frozen=True)
class Settings:
    rate_limit_per_minute: int = 20
    cors_origins: tuple[str, ...] = ("http://localhost:3000",)
    dns_timeout: float = 3.0
    dns_nameservers: tuple[str, ...] = ()
    dns_port: int = 53
    trust_proxy_headers: bool = False

    @classmethod
    def from_env(cls) -> Settings:
        origins = os.getenv("CORS_ORIGINS", "http://localhost:3000")
        nameservers = os.getenv("DNS_NAMESERVERS", "")
        return cls(
            rate_limit_per_minute=int(os.getenv("RATE_LIMIT_PER_MINUTE", "20")),
            cors_origins=tuple(o.strip() for o in origins.split(",") if o.strip()),
            dns_timeout=float(os.getenv("DNS_TIMEOUT_SECONDS", "3")),
            dns_nameservers=tuple(n.strip() for n in nameservers.split(",") if n.strip()),
            dns_port=int(os.getenv("DNS_PORT", "53")),
            trust_proxy_headers=os.getenv("TRUST_PROXY_HEADERS", "false").lower() == "true",
        )


def _client_key(request: Request, trust_proxy_headers: bool) -> str:
    if trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def create_app(
    resolver: Resolver | None = None,
    limiter: SlidingWindowLimiter | None = None,
    settings: Settings | None = None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    resolver = resolver or DnsPythonResolver(
        timeout=settings.dns_timeout,
        nameservers=list(settings.dns_nameservers) or None,
        port=settings.dns_port,
    )
    limiter = limiter or SlidingWindowLimiter(settings.rate_limit_per_minute, 60.0)

    app = FastAPI(
        title="DNS and Email Health Checker",
        version="1.0.0",
        description="Checks MX, SPF, DKIM and DMARC records for a domain. Read-only DNS lookups.",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/check", response_model=CheckResponse)
    def check(payload: CheckRequest, request: Request) -> CheckResponse:
        allowed, retry_after = limiter.check(_client_key(request, settings.trust_proxy_headers))
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail="Too many requests. Try again shortly.",
                headers={"Retry-After": str(int(retry_after) + 1)},
            )
        try:
            domain = normalize_domain(payload.domain)
            selectors = normalize_selectors(payload.dkim_selectors)
        except InvalidInput as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        try:
            return run_checks(resolver, domain, selectors)
        except DomainNotFound as exc:
            raise HTTPException(status_code=404, detail=f"{domain} does not exist in DNS.") from exc
        except DNSLookupError as exc:
            logger.warning("DNS failure for %s: %s", domain, exc)
            raise HTTPException(status_code=502, detail="DNS lookup failed. Try again.") from exc

    return app


app = create_app()
