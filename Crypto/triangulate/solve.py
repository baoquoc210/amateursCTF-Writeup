from Crypto.Util.number import long_to_bytes, GCD, isPrime


def main() -> None:
    outputs = [
        1471207943545852478106618608447716459893047706734102352763789322304413594294954078951854930241394509747415,
        1598692736073482992170952603470306867921209728727115430390864029776876148087638761351349854291345381739153,
        7263027854980708582516705896838975362413360736887495919458129587084263748979742208194554859835570092536173,
        1421793811298953348672614691847135074360107904034360298926919347912881575026291936258693160494676689549954,
        7461500488401740536173753018264993398650307817555091262529778478859878439497126612121005384358955488744365,
        7993378969370214846258034508475124464164228761748258400865971489460388035990421363365750583336003815658573,
    ]

    O1, O2, O3, O4, O5, O6 = outputs

    # Linear relation for X from (a^2)(a^3) = a^5
    C1 = (O3 + O4) - (O5 + O1)
    C0 = (O3 * O4) - (O5 * O1)

    # Quadratic relation from (a^2)^2 = a^4
    u, v = O2, O3
    w, z = O4, O1

    A_quad = (2 * u + v) - (w + 2 * z)
    B_quad = (u * u + 2 * u * v) - (2 * z * w + z * z)
    C_quad = (u * u * v) - (w * z * z)

    Val = A_quad * ((-C0) ** 2) + B_quad * (-C0) * C1 + C_quad * (C1 ** 2)
    candidate_m = abs(Val)

    # Second relation from a^2 * a^4 = a^6
    u, v, w = O2, O4, O5
    up, vp, wp = O6, O1, O3

    A_rel2 = (u + v + w) - (up + vp + wp)
    B_rel2 = (u * v + v * w + w * u) - (up * vp + vp * wp + wp * up)
    C_rel2 = (u * v * w) - (up * vp * wp)

    Val2 = A_rel2 * ((-C0) ** 2) + B_rel2 * (-C0) * C1 + C_rel2 * (C1 ** 2)

    m_full = GCD(candidate_m, abs(Val2))

    # Strip powers of 2
    while m_full % 2 == 0:
        m_full //= 2

    # The resulting modulus is 3 * prime, take the prime factor
    if m_full % 3 != 0:
        raise ValueError("Unexpected modulus structure")

    m = m_full // 3

    # Basic sanity check
    if not isPrime(m):
        raise ValueError("Recovered modulus is not prime")

    # Solve for X
    X = (-C0 * pow(C1, -1, m)) % m

    # Recover a using a = (O3+X)(O1+X)/(O2+X)^2
    num = (O3 + X) * (O1 + X)
    den = pow(O2 + X, 2, m)
    a = (num * pow(den, -1, m)) % m

    # Recover initial seed S0 = flag
    inv_a = pow(a, -1, m)
    S0 = ((O1 + X) * inv_a - X) % m

    flag = long_to_bytes(S0)
    print(flag.decode())


if __name__ == "__main__":
    main()

