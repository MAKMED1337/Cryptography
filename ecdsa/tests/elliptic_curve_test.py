import pytest

from ..elliptic_curve import NormalPoint, PointAtInfinity, secp256k1

G = secp256k1.G

# All the points have a "positive" y
points: list[NormalPoint] = [
    G,
    # Random points:
    NormalPoint(1337, 0x841F4ADF5FCC5CD3A744A1233BFA4CE6A64F3E366CC20FB3E89E6C5DF72BE2F5),
]


def test_is_valid() -> None:
    for p in points:
        assert secp256k1.is_valid(p)
    assert secp256k1.is_valid(PointAtInfinity())

    assert not secp256k1.is_valid(NormalPoint(0, 0))
    assert not secp256k1.is_valid(NormalPoint(0, 1))
    assert not secp256k1.is_valid(NormalPoint(G.x, G.y + 1))


def test_get_y() -> None:
    for p in points:
        assert secp256k1.get_y(p.x, negative=False) == p.y
        assert secp256k1.get_y(p.x, negative=True) == secp256k1.p - p.y

    with pytest.raises(ValueError):  # noqa: PT011
        secp256k1.get_y(5, negative=True)

    with pytest.raises(ValueError):  # noqa: PT011
        secp256k1.get_y(0, negative=True)


def test_addition() -> None:
    assert isinstance(secp256k1.add(PointAtInfinity(), PointAtInfinity()), PointAtInfinity)

    for p in points:
        assert isinstance(secp256k1.add(p, NormalPoint(p.x, secp256k1.p - p.y)), PointAtInfinity)
        assert secp256k1.add(p, PointAtInfinity()) == p
        assert secp256k1.add(PointAtInfinity(), p) == p

    # check associativity
    assert secp256k1.add(points[0], points[1]) == secp256k1.add(points[1], points[0])

    # tested using http://christelbach.com/ECCalculator.aspx
    assert secp256k1.add(G, G) == NormalPoint(
        0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5, 0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A
    )

    assert secp256k1.add(points[1], points[1]) == NormalPoint(
        0x5DDB0C1AE610970A373086C8A89A09E29041023F694296951CA5E3278AA96595, 0xBEE66A1BEB684022CDA8695C1666F4103B0D655B619B8487FF563D537A4F47C2
    )

    assert secp256k1.add(points[0], points[1]) == NormalPoint(
        0x867AB220B6EB72C164D1DDB513679431FC945EA6B8F164738044B15900CD24A4, 0x6AFC5CFAD81C65E31DB8345C3473FD5D858AEDA44C2AF30CC23CD7A14D47C972
    )


def test_multiplication() -> None:
    assert isinstance(secp256k1.multiply(PointAtInfinity(), 0), PointAtInfinity)
    for p in points:
        assert isinstance(secp256k1.multiply(p, 0), PointAtInfinity)
        assert secp256k1.multiply(p, 1) == p
        res = p
        for i in range(1, 100):
            assert secp256k1.multiply(p, i) == res
            res = secp256k1.add(res, p)
