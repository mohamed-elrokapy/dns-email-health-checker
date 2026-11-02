from app.checks.dmarc import check_dmarc
from app.models import Status
from tests.conftest import FakeResolver

D = "example.com"


def run(*records: str):
    return check_dmarc(FakeResolver(txt={f"_dmarc.{D}": list(records)}), D)


def test_missing_fails():
    assert check_dmarc(FakeResolver(), D).status is Status.FAIL


def test_multiple_records_fail():
    assert run("v=DMARC1; p=none", "v=DMARC1; p=reject").status is Status.FAIL


def test_monitoring_mode_warns():
    result = run("v=DMARC1; p=none; rua=mailto:r@example.com")
    assert result.status is Status.WARN
    assert "monitoring" in result.summary


def test_enforced_policies_pass():
    assert run("v=DMARC1; p=quarantine; rua=mailto:r@example.com").status is Status.PASS
    assert run("v=DMARC1; p=reject; rua=mailto:r@example.com").status is Status.PASS


def test_invalid_or_missing_policy_fails():
    assert run("v=DMARC1; p=block").status is Status.FAIL
    assert run("v=DMARC1; rua=mailto:r@example.com").status is Status.FAIL


def test_partial_pct_downgrades_a_pass():
    result = run("v=DMARC1; p=reject; pct=25; rua=mailto:r@example.com")
    assert result.status is Status.WARN
    assert any("pct=25" in d for d in result.details)


def test_non_numeric_pct_is_reported():
    result = run("v=DMARC1; p=reject; pct=abc; rua=mailto:r@example.com")
    assert result.status is Status.WARN


def test_missing_rua_is_noted_without_failing():
    result = run("v=DMARC1; p=reject")
    assert result.status is Status.PASS
    assert any("rua" in d for d in result.details)


def test_invalid_subdomain_policy_warns():
    result = run("v=DMARC1; p=reject; sp=nope; rua=mailto:r@example.com")
    assert result.status is Status.WARN


def test_spacing_in_version_tag_is_tolerated():
    assert run("v = DMARC1 ; p=reject").status is Status.PASS
