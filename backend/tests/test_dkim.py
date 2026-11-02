from app.checks.dkim import check_dkim
from app.models import Status
from tests.conftest import FakeResolver

D = "example.com"


def name(selector: str) -> str:
    return f"{selector}._domainkey.{D}"


def test_valid_2048_key_passes(rsa2048_record):
    r = FakeResolver(txt={name("selector1"): [rsa2048_record]})
    result = check_dkim(r, D)
    assert result.status is Status.PASS
    assert "selector1" in " ".join(result.details)


def test_1024_bit_key_warns(rsa1024_record):
    r = FakeResolver(txt={name("google"): [rsa1024_record]})
    result = check_dkim(r, D)
    assert result.status is Status.WARN
    assert "1024" in " ".join(result.details)


def test_revoked_key_fails():
    r = FakeResolver(txt={name("default"): ["v=DKIM1; k=rsa; p="]})
    result = check_dkim(r, D)
    assert result.status is Status.FAIL
    assert "revoked" in " ".join(result.details)


def test_invalid_base64_and_invalid_key_fail():
    bad64 = FakeResolver(txt={name("default"): ["v=DKIM1; p=!!!notbase64!!!"]})
    assert check_dkim(bad64, D).status is Status.FAIL
    badkey = FakeResolver(txt={name("default"): ["v=DKIM1; p=aGVsbG8gd29ybGQ="]})
    assert check_dkim(badkey, D).status is Status.FAIL


def test_ed25519_key_length_is_validated():
    ok = "v=DKIM1; k=ed25519; p=" + "A" * 43 + "="
    assert check_dkim(FakeResolver(txt={name("s1"): [ok]}), D).status is Status.PASS
    short = "v=DKIM1; k=ed25519; p=QUJD"
    assert check_dkim(FakeResolver(txt={name("s1"): [short]}), D).status is Status.FAIL


def test_nothing_found_with_common_selectors_warns():
    result = check_dkim(FakeResolver(), D)
    assert result.status is Status.WARN
    assert "arbitrary" in " ".join(result.details)


def test_nothing_found_for_requested_selector_fails():
    result = check_dkim(FakeResolver(), D, ["mysel"])
    assert result.status is Status.FAIL
    assert "mysel" in " ".join(result.details)


def test_requested_selector_is_found(rsa2048_record):
    r = FakeResolver(txt={name("mysel"): [rsa2048_record]})
    result = check_dkim(r, D, ["mysel"])
    assert result.status is Status.PASS


def test_lookup_error_for_one_selector_is_reported_as_warning(rsa2048_record):
    r = FakeResolver(txt={name("selector1"): [rsa2048_record]}, failing={name("selector2")})
    result = check_dkim(r, D)
    assert result.status is Status.WARN
    assert "selector2" in " ".join(result.details)
