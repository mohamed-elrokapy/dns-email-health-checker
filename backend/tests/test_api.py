import pytest
from fastapi.testclient import TestClient

from app.main import Settings, create_app
from app.ratelimit import SlidingWindowLimiter
from tests.conftest import FakeResolver

D = "example.com"


def healthy_resolver(rsa_record: str) -> FakeResolver:
    return FakeResolver(
        txt={
            D: ["v=spf1 ip4:192.0.2.0/24 -all"],
            f"_dmarc.{D}": ["v=DMARC1; p=reject; rua=mailto:r@example.com"],
            f"selector1._domainkey.{D}": [rsa_record],
        },
        mx={D: [(10, "mx1.mail.net"), (20, "mx2.mail.net")]},
        addresses={"mx1.mail.net": ["192.0.2.1"], "mx2.mail.net": ["192.0.2.2"]},
    )


def client(resolver, limit: int = 100, settings: Settings | None = None) -> TestClient:
    app = create_app(resolver, SlidingWindowLimiter(limit, 60), settings or Settings())
    return TestClient(app)


def test_health():
    assert client(FakeResolver()).get("/health").json() == {"status": "ok"}


def test_healthy_domain_returns_all_four_checks(rsa2048_record):
    response = client(healthy_resolver(rsa2048_record)).post("/api/check", json={"domain": D})
    assert response.status_code == 200
    body = response.json()
    assert body["domain"] == D
    assert body["overall"] == "pass"
    assert [c["id"] for c in body["checks"]] == ["mx", "spf", "dkim", "dmarc"]


def test_overall_is_the_worst_status(rsa2048_record):
    resolver = healthy_resolver(rsa2048_record)
    resolver._txt.pop(f"_dmarc.{D}")
    body = client(resolver).post("/api/check", json={"domain": D}).json()
    assert body["overall"] == "fail"


def test_domain_is_normalised_in_the_response(rsa2048_record):
    response = client(healthy_resolver(rsa2048_record)).post(
        "/api/check", json={"domain": " EXAMPLE.com. "}
    )
    assert response.json()["domain"] == D


def test_custom_dkim_selector_is_used(rsa2048_record):
    resolver = healthy_resolver(rsa2048_record)
    resolver._txt[f"custom._domainkey.{D}"] = [rsa2048_record]
    body = (
        client(resolver).post("/api/check", json={"domain": D, "dkim_selectors": ["Custom"]}).json()
    )
    dkim = next(c for c in body["checks"] if c["id"] == "dkim")
    assert "custom" in " ".join(dkim["details"])


@pytest.mark.parametrize(
    "payload",
    [
        {"domain": "192.168.0.1"},
        {"domain": "localhost"},
        {"domain": "bad domain.com"},
        {"domain": D, "dkim_selectors": ["bad selector"]},
    ],
)
def test_invalid_input_returns_422(payload):
    assert client(FakeResolver()).post("/api/check", json=payload).status_code == 422


def test_schema_violations_return_422():
    c = client(FakeResolver())
    assert c.post("/api/check", json={}).status_code == 422
    assert c.post("/api/check", json={"domain": "x"}).status_code == 422
    too_many = {"domain": D, "dkim_selectors": [f"s{i}" for i in range(11)]}
    assert c.post("/api/check", json=too_many).status_code == 422


def test_nxdomain_returns_404():
    response = client(FakeResolver(existing=False)).post("/api/check", json={"domain": D})
    assert response.status_code == 404


def test_dns_outage_returns_502():
    resolver = FakeResolver(failing={D})
    assert client(resolver).post("/api/check", json={"domain": D}).status_code == 502


def test_single_check_failure_degrades_to_warning_not_error(rsa2048_record):
    resolver = healthy_resolver(rsa2048_record)
    resolver._failing = {f"_dmarc.{D}"}
    response = client(resolver).post("/api/check", json={"domain": D})
    assert response.status_code == 200
    dmarc = next(c for c in response.json()["checks"] if c["id"] == "dmarc")
    assert dmarc["status"] == "warn"
    assert "could not be completed" in dmarc["summary"]


def test_rate_limit_returns_429_with_retry_after(rsa2048_record):
    c = client(healthy_resolver(rsa2048_record), limit=2)
    assert c.post("/api/check", json={"domain": D}).status_code == 200
    assert c.post("/api/check", json={"domain": D}).status_code == 200
    blocked = c.post("/api/check", json={"domain": D})
    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) >= 1


def test_forwarded_header_is_only_trusted_when_enabled(rsa2048_record):
    resolver = healthy_resolver(rsa2048_record)
    trusted = client(resolver, limit=1, settings=Settings(trust_proxy_headers=True))
    first = trusted.post("/api/check", json={"domain": D}, headers={"X-Forwarded-For": "1.1.1.1"})
    other = trusted.post("/api/check", json={"domain": D}, headers={"X-Forwarded-For": "2.2.2.2"})
    assert first.status_code == other.status_code == 200

    untrusted = client(resolver, limit=1)
    a = untrusted.post("/api/check", json={"domain": D}, headers={"X-Forwarded-For": "1.1.1.1"})
    b = untrusted.post("/api/check", json={"domain": D}, headers={"X-Forwarded-For": "2.2.2.2"})
    assert (a.status_code, b.status_code) == (200, 429)


def test_settings_from_env(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_PER_MINUTE", "5")
    monkeypatch.setenv("CORS_ORIGINS", "https://a.example, https://b.example")
    monkeypatch.setenv("DNS_TIMEOUT_SECONDS", "1.5")
    monkeypatch.setenv("TRUST_PROXY_HEADERS", "true")
    monkeypatch.setenv("DNS_NAMESERVERS", "1.1.1.1, 9.9.9.9")
    monkeypatch.setenv("DNS_PORT", "5353")
    settings = Settings.from_env()
    assert settings.dns_nameservers == ("1.1.1.1", "9.9.9.9")
    assert settings.dns_port == 5353
    assert settings.rate_limit_per_minute == 5
    assert settings.cors_origins == ("https://a.example", "https://b.example")
    assert settings.dns_timeout == 1.5
    assert settings.trust_proxy_headers is True
