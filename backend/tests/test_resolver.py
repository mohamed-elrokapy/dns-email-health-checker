"""Tests for the dnspython adapter, against a local DNS server (no internet needed)."""

import pytest

from app.models import Status
from app.resolver import DNSLookupError, DnsPythonResolver
from app.service import run_checks
from tests.conftest import dkim_record
from tests.dnsserver import LocalDnsServer, txt_rdata

SOA = "ns1.example.com. admin.example.com. 1 7200 3600 1209600 300"


@pytest.fixture(scope="module")
def zone_records() -> list[tuple[str, str, str]]:
    dkim = dkim_record(2048)  # longer than 255 characters, so it is split into chunks
    assert len(dkim) > 255
    return [
        ("example.com", "SOA", SOA),
        ("example.com", "MX", "10 mx1.example.com."),
        ("example.com", "MX", "20 mx2.example.com."),
        ("example.com", "TXT", txt_rdata("v=spf1 ip4:192.0.2.0/24 -all")),
        ("mx1.example.com", "A", "192.0.2.10"),
        ("mx2.example.com", "AAAA", "2001:db8::2"),
        ("_dmarc.example.com", "TXT", txt_rdata("v=DMARC1; p=reject; rua=mailto:r@example.com")),
        ("selector1._domainkey.example.com", "TXT", txt_rdata(dkim)),
        ("broken.example.com", "SOA", SOA),
    ]


@pytest.fixture
def resolver(zone_records):
    with LocalDnsServer(zone_records, servfail={"flaky.example.com"}) as server:
        yield DnsPythonResolver(timeout=1.0, nameservers=["127.0.0.1"], port=server.port)


def test_txt_chunks_are_joined(resolver, zone_records):
    [record] = resolver.txt("selector1._domainkey.example.com")
    assert record.startswith("v=DKIM1; k=rsa; p=")
    assert len(record) > 255


def test_mx_and_addresses(resolver):
    assert sorted(resolver.mx("example.com")) == [(10, "mx1.example.com"), (20, "mx2.example.com")]
    assert resolver.addresses("mx1.example.com") == ["192.0.2.10"]
    assert resolver.addresses("mx2.example.com") == ["2001:db8::2"]


def test_missing_names_and_types_are_empty_not_errors(resolver):
    assert resolver.txt("nothing.example.com") == []  # NXDOMAIN
    assert resolver.txt("mx1.example.com") == []  # name exists, no TXT (NODATA)
    assert resolver.mx("mx1.example.com") == []


def test_domain_exists(resolver):
    assert resolver.domain_exists("example.com") is True
    assert resolver.domain_exists("mx1.example.com") is True  # exists, no SOA (NODATA)
    assert resolver.domain_exists("does-not-exist.org") is False


def test_server_failure_raises_dns_lookup_error(resolver):
    with pytest.raises(DNSLookupError):
        resolver.txt("flaky.example.com")
    with pytest.raises(DNSLookupError):
        resolver.domain_exists("flaky.example.com")


def test_unreachable_nameserver_raises_dns_lookup_error():
    dead = DnsPythonResolver(timeout=0.4, nameservers=["127.0.0.1"], port=9)
    with pytest.raises(DNSLookupError):
        dead.txt("example.com")
    with pytest.raises(DNSLookupError):
        dead.domain_exists("example.com")


def test_full_run_against_the_real_adapter(resolver):
    result = run_checks(resolver, "example.com", [])
    assert result.overall is Status.PASS
    assert {c.id: c.status for c in result.checks} == {
        "mx": Status.PASS,
        "spf": Status.PASS,
        "dkim": Status.PASS,
        "dmarc": Status.PASS,
    }
