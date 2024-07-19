from dataclasses import dataclass


@dataclass
class NormalPoint:
    x: int
    y: int


class PointAtInfinity:
    pass


Point = NormalPoint | PointAtInfinity


class EllipticCurve:
    # y^2 = x^3 + ax + b (mod p)
    a: int
    b: int
    p: int

    G: NormalPoint
    n: int

    # Constructor does not check if p is indeed prime
    def __init__(self, a: int, b: int, p: int, G: NormalPoint, n: int):  # noqa: N803
        if p % 4 != 3:  # noqa: PLR2004
            raise ValueError('Prime number should be 3 modulo 4 for performing sqrt')

        self.a = a
        self.b = b
        self.p = p
        self.G = G
        self.n = n

    def is_valid(self, p: Point) -> bool:
        if isinstance(p, PointAtInfinity):
            return True

        return (p.x**3 + self.a * p.x + self.b - p.y**2) % self.p == 0

    # https://koclab.cs.ucsb.edu/teaching/ccs130h/2013/w00e-sqrt.pdf
    def get_y(self, x: int, negative: bool) -> int:  # noqa: FBT001
        rhs = x**3 + self.a * x + self.b

        u = pow(rhs, (self.p - 1) // 2, self.p)
        if u == self.p - 1:
            msg = f'Y does not exist for x = {x}'
            raise ValueError(msg)

        y = pow(rhs, (self.p + 1) // 4, self.p)
        return (-y) % self.p if negative else y

    # https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication
    def add(self, p: Point, q: Point) -> Point:
        if isinstance(p, PointAtInfinity):
            return q
        if isinstance(q, PointAtInfinity):
            return p

        if p.x == q.x and p.y != q.y:
            return PointAtInfinity()

        def get_lambda() -> int:
            if p.x != q.x:
                return (q.y - p.y) * pow(q.x - p.x, -1, self.p) % self.p
            return (3 * p.x**2 + self.a) * pow(2 * p.y, -1, self.p) % self.p

        lam = get_lambda()
        r_x = (lam**2 - p.x - q.x) % self.p
        return NormalPoint(r_x, (lam * (p.x - r_x) - p.y) % self.p)

    def multiply(self, p: Point, k: int) -> Point:
        res: Point = PointAtInfinity()
        while k:
            if k & 1:
                res = self.add(res, p)

            p = self.add(p, p)
            k >>= 1
        return res


# https://en.bitcoin.it/wiki/Secp256k1
secp256k1 = EllipticCurve(
    0,
    7,
    (1 << 256) - (1 << 32) - (1 << 9) - (1 << 8) - (1 << 7) - (1 << 6) - (1 << 4) - 1,
    NormalPoint(
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    ),
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
)
