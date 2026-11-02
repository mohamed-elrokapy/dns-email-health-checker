from app.checks.mx import check_mx
from app.models import Status
from tests.conftest import FakeResolver

D = "example.com"


def test_healthy_mx_passes():
    r = FakeResolver(
        mx={D: [(20, "mx2.mail.net"), (10, "mx1.mail.net")]},
        addresses={"mx1.mail.net": ["192.0.2.1"], "mx2.mail.net": ["192.0.2.2"]},
    )
    result = check_mx(r, D)
    assert result.status is Status.PASS
    assert result.records[0].startswith("10 ")


def test_no_mx_but_address_warns():
    result = check_mx(FakeResolver(addresses={D: ["192.0.2.9"]}), D)
    assert result.status is Status.WARN


def test_no_mx_and_no_address_fails():
    assert check_mx(FakeResolver(), D).status is Status.FAIL


def test_null_mx_is_informational():
    result = check_mx(FakeResolver(mx={D: [(0, "")]}), D)
    assert result.status is Status.INFO


def test_unresolvable_hosts_fail_or_warn():
    all_bad = FakeResolver(mx={D: [(10, "a.mail.net"), (20, "b.mail.net")]})
    assert check_mx(all_bad, D).status is Status.FAIL
    some_bad = FakeResolver(
        mx={D: [(10, "a.mail.net"), (20, "b.mail.net")]}, addresses={"a.mail.net": ["192.0.2.1"]}
    )
    assert check_mx(some_bad, D).status is Status.WARN


def test_single_mx_notes_missing_failover():
    r = FakeResolver(mx={D: [(10, "a.mail.net")]}, addresses={"a.mail.net": ["192.0.2.1"]})
    result = check_mx(r, D)
    assert result.status is Status.PASS
    assert any("failover" in d for d in result.details)
