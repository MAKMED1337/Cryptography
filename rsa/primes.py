import secrets

ROUNDS = 100


# https://www.geeksforgeeks.org/primality-test-set-3-miller-rabin/
def rabin_miller(n: int, d: int) -> bool:
    a = secrets.randbelow(n - 3) + 2  # [2, n - 2]
    x = pow(a, d, n)
    if x in (1, n - 1):
        return True

    while d != n - 1:
        x = x * x % n
        d *= 2

        if x == 1:
            return False
        if x == n - 1:
            return True

    return False


# The probability of a false positive is (1/2)^rounds
def is_prime(n: int, rounds: int = ROUNDS) -> bool:
    # small cases
    for i in range(2, 30):
        if n % i == 0:
            return n == i

    d = n - 1
    while d % 2 == 0:
        d //= 2

    return all(rabin_miller(n, d) for _ in range(rounds))


# Returns a random from range [2, n)
def random_prime(n: int) -> int:
    while True:
        x = secrets.randbelow(n)
        if is_prime(x):
            return x
