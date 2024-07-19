from ..primes import is_prime, random_prime

MAX = 100000


def slow_is_prime(n: int) -> bool:
    i = 2
    while i * i <= n:
        if n % i == 0:
            return False
        i += 1
    return True


def test_checker() -> None:
    assert is_prime(2)
    assert is_prime(3)
    assert is_prime(257)
    assert is_prime(100000103729)
    assert is_prime(100000103711)

    assert not is_prime(256)
    assert not is_prime(255)
    assert not is_prime(100000103711 * 100000103729)

    for n in range(2, 1000):
        assert slow_is_prime(n) == is_prime(n)


def test_generator() -> None:
    for _ in range(100):
        n = random_prime(MAX)
        assert 1 < n < MAX
        assert slow_is_prime(n)
