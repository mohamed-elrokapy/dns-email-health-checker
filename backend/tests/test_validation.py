import pytest

from app.validation import InvalidInput, normalize_domain, normalize_selectors


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "example.com"),
        ("  Example.COM. ", "example.com"),
        ("sub.example.co.uk", "sub.example.co.uk"),
        ("bücher.de", "xn--bcher-kva.de"),
    ],
)
def test_normalize_domain_accepts_and_normalises(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "localhost",
        "singlelabel",
        "192.168.0.1",
        "2001:db8::1",
        "exa mple.com",
        "-bad.com",
        "bad-.com",
        "a" * 64 + ".com",
        "x." * 130 + "com",
        "printer.local",
        "host.internal",
        "1.2.arpa",
        "example.123",
        "exa_mple.com",
        "http://example.com",
    ],
)
def test_normalize_domain_rejects_bad_input(raw):
    with pytest.raises(InvalidInput):
        normalize_domain(raw)


def test_normalize_selectors_dedupes_and_lowercases():
    assert normalize_selectors(["Selector1", "selector1", " s2 "]) == ["selector1", "s2"]


@pytest.mark.parametrize("bad", ["", "-x", "x y", "a;b", "x" * 64, "../x"])
def test_normalize_selectors_rejects_bad_input(bad):
    with pytest.raises(InvalidInput):
        normalize_selectors([bad])


def test_normalize_selectors_limits_count():
    with pytest.raises(InvalidInput):
        normalize_selectors([f"s{i}" for i in range(11)])
