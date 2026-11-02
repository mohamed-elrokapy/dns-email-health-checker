import pytest

from app.ratelimit import SlidingWindowLimiter


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_allows_up_to_limit_then_blocks_with_retry_after():
    clock = Clock()
    limiter = SlidingWindowLimiter(2, 60, clock)
    assert limiter.check("a") == (True, 0.0)
    clock.now += 10
    assert limiter.check("a") == (True, 0.0)
    allowed, retry = limiter.check("a")
    assert not allowed
    assert retry == pytest.approx(50.0)


def test_window_slides_and_keys_are_independent():
    clock = Clock()
    limiter = SlidingWindowLimiter(1, 60, clock)
    assert limiter.check("a")[0]
    assert not limiter.check("a")[0]
    assert limiter.check("b")[0]
    clock.now += 61
    assert limiter.check("a")[0]


def test_invalid_configuration_is_rejected():
    with pytest.raises(ValueError):
        SlidingWindowLimiter(0, 60)
    with pytest.raises(ValueError):
        SlidingWindowLimiter(1, 0)


def test_stale_keys_are_evicted():
    clock = Clock()
    limiter = SlidingWindowLimiter(1, 60, clock)
    for i in range(10_001):
        limiter.check(f"k{i}")
    clock.now += 120
    limiter.check("fresh")
    assert len(limiter._hits) < 10_001
