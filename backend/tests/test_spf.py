from app.checks.spf import check_spf
from app.models import Status
from tests.conftest import FakeResolver

D = "example.com"


def resolver(**txt: list[str]) -> FakeResolver:
    return FakeResolver(txt={name.replace("__", "."): v for name, v in txt.items()})


def test_missing_record_fails():
    result = check_spf(FakeResolver(), D)
    assert result.status is Status.FAIL
    assert "No SPF" in result.summary


def test_multiple_records_fail():
    r = FakeResolver(txt={D: ["v=spf1 -all", "v=spf1 ~all"]})
    assert check_spf(r, D).status is Status.FAIL


def test_strict_policy_passes_and_counts_lookups():
    r = FakeResolver(
        txt={
            D: ["v=spf1 ip4:192.0.2.0/24 include:_spf.vendor.com mx -all"],
            "_spf.vendor.com": ["v=spf1 a ip4:198.51.100.0/24 -all"],
        }
    )
    result = check_spf(r, D)
    assert result.status is Status.PASS
    assert "3/10" in result.summary


def test_softfail_passes_with_hint():
    r = FakeResolver(txt={D: ["v=spf1 ip4:192.0.2.1 ~all"]})
    result = check_spf(r, D)
    assert result.status is Status.PASS
    assert any("-all" in d for d in result.details)


def test_plus_all_fails():
    r = FakeResolver(txt={D: ["v=spf1 +all"]})
    assert check_spf(r, D).status is Status.FAIL


def test_bare_all_means_plus_all():
    r = FakeResolver(txt={D: ["v=spf1 all"]})
    assert check_spf(r, D).status is Status.FAIL


def test_neutral_and_missing_all_warn():
    assert check_spf(FakeResolver(txt={D: ["v=spf1 ?all"]}), D).status is Status.WARN
    assert check_spf(FakeResolver(txt={D: ["v=spf1 ip4:192.0.2.1"]}), D).status is Status.WARN


def test_more_than_ten_lookups_fails():
    includes = " ".join(f"include:s{i}.vendor.com" for i in range(11))
    txt = {D: [f"v=spf1 {includes} -all"]}
    txt.update({f"s{i}.vendor.com": ["v=spf1 ip4:192.0.2.1 -all"] for i in range(11)})
    result = check_spf(FakeResolver(txt=txt), D)
    assert result.status is Status.FAIL
    assert "11 DNS lookups" in " ".join(result.details)


def test_nine_lookups_warns():
    terms = " ".join(f"a:h{i}.example.com" for i in range(9))
    result = check_spf(FakeResolver(txt={D: [f"v=spf1 {terms} -all"]}), D)
    assert result.status is Status.WARN


def test_include_without_spf_fails():
    r = FakeResolver(txt={D: ["v=spf1 include:gone.vendor.com -all"]})
    result = check_spf(r, D)
    assert result.status is Status.FAIL
    assert "gone.vendor.com" in " ".join(result.details)


def test_include_with_two_records_fails():
    r = FakeResolver(
        txt={D: ["v=spf1 include:dup.vendor.com -all"], "dup.vendor.com": ["v=spf1 -all"] * 2}
    )
    assert check_spf(r, D).status is Status.FAIL


def test_include_loop_is_detected():
    r = FakeResolver(
        txt={
            D: ["v=spf1 include:a.example.net -all"],
            "a.example.net": ["v=spf1 include:b.example.net -all"],
            "b.example.net": ["v=spf1 include:a.example.net -all"],
        }
    )
    result = check_spf(r, D)
    assert result.status is Status.FAIL
    assert any("loop" in d for d in result.details)


def test_deep_nesting_is_cut_off():
    txt = {D: ["v=spf1 include:n0.example.net -all"]}
    for i in range(15):
        txt[f"n{i}.example.net"] = [f"v=spf1 include:n{i + 1}.example.net -all"]
    result = check_spf(FakeResolver(txt=txt), D)
    assert result.status is Status.FAIL
    assert any("deeper" in d for d in result.details)


def test_ptr_is_deprecated():
    result = check_spf(FakeResolver(txt={D: ["v=spf1 ptr -all"]}), D)
    assert result.status is Status.WARN


def test_redirect_counts_and_replaces_all():
    r = FakeResolver(
        txt={
            D: ["v=spf1 redirect=_spf.vendor.com"],
            "_spf.vendor.com": ["v=spf1 ip4:192.0.2.1 -all"],
        }
    )
    result = check_spf(r, D)
    assert result.status is Status.PASS
    assert "1/10" in result.summary


def test_modifiers_and_empty_include_are_handled():
    r = FakeResolver(txt={D: ["v=spf1 exp=explain.example.com include: -all"]})
    assert check_spf(r, D).status is Status.FAIL
