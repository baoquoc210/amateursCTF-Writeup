import re
import socket
import sys
from random import getrandbits


def recv_until(sock, marker: bytes) -> bytes:
    data = bytearray()
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError("connection closed")
        data += chunk
    return bytes(data)


def poly_strip(p, n):
    if not p:
        return [0]
    while len(p) > 1 and p[-1] % n == 0:
        p.pop()
    return [c % n for c in p]


def poly_divmod(a, b, n):
    a = a[:]
    b = poly_strip(b[:], n)
    if len(b) == 0:
        raise ValueError("zero divisor")
    la, lb = len(a), len(b)
    if la < lb:
        return [0], poly_strip(a, n)
    try:
        inv_lc = pow(b[-1] % n, -1, n)
    except ValueError:
        # leading coefficient not invertible modulo n
        raise
    q = [0] * (la - lb + 1)
    for k in range(la - lb, -1, -1):
        coeff = a[lb - 1 + k] * inv_lc % n
        q[k] = coeff
        if coeff:
            for j in range(lb):
                a[j + k] = (a[j + k] - coeff * b[j]) % n
    return poly_strip(q, n), poly_strip(a, n)


def poly_gcd(a, b, n):
    a = poly_strip(a, n)
    b = poly_strip(b, n)
    while not (len(b) == 1 and b[0] % n == 0):
        try:
            _, r = poly_divmod(a, b, n)
        except ValueError:
            # give up on this gcd if division fails
            return [1]
        a, b = b, r
    a = poly_strip(a, n)
    lc = a[-1] % n
    try:
        inv_lc = pow(lc, -1, n)
        a = [(c * inv_lc) % n for c in a]
    except ValueError:
        pass
    return poly_strip(a, n)


def poly_from_shifted_cube(s, c, n):
    s %= n
    c %= n
    s2 = (s * s) % n
    s3 = (s2 * s) % n
    # (x + s)^3 - c = x^3 + 3 s x^2 + 3 s^2 x + (s^3 - c)
    return [(s3 - c) % n, (3 * s2) % n, (3 * s) % n, 1]


def main():
    host = "amt.rs"
    port = 43433

    sock = socket.create_connection((host, port))

    # receive initial banner up to the first prompt
    banner = recv_until(sock, b"scramble the flag: ")
    text = banner.decode()
    m = re.search(r"\((\d+),\s*3\)", text)
    if not m:
        print("Failed to parse modulus from banner:", text)
        return
    n = int(m.group(1))
    e = 3
    print("Parsed n bits:", n.bit_length(), file=sys.stderr)

    samples = []  # list of (s, c, poly)
    max_queries = 2000

    for q in range(max_queries):
        # choose a random scramble
        s_val = getrandbits(256) % n
        # send scramble
        sock.sendall(str(s_val).encode() + b"\n")

        # receive until next prompt (includes 'scrambling...' and 'c = ...')
        data = recv_until(sock, b"scramble the flag: ")
        text = data.decode()

        m = re.search(r"c\s*=\s*(\d+)", text)
        if not m:
            print("Failed to parse ciphertext from response:", text)
            return
        c_val = int(m.group(1))

        P = poly_from_shifted_cube(s_val, c_val, n)

        # try gcd with all previous samples
        for (s2, c2, P2) in samples:
            G = poly_gcd(P, P2, n)
            if len(G) == 2:
                a0, a1 = G[0], G[1]
                try:
                    inv_a1 = pow(a1, -1, n)
                except ValueError:
                    continue
                root = (-a0 * inv_a1) % n
                # verify root against both queries
                if pow((root + s_val) % n, e, n) == c_val and pow(
                    (root + s2) % n, e, n
                ) == c2:
                    print("Recovered cs =", root, file=sys.stderr)
                    cs = root
                    # extract flag from high bits: cs = flag<<256 + noise
                    F = (cs >> 256) << 256
                    flag_int = F >> 256
                    # 72 bytes by challenge description
                    try:
                        flag_bytes = flag_int.to_bytes(72, "big")
                    except OverflowError:
                        # fallback: derive length from bit_length
                        length = (flag_int.bit_length() + 7) // 8
                        flag_bytes = flag_int.to_bytes(length, "big")
                    print(flag_bytes)
                    sock.close()
                    return

        samples.append((s_val, c_val, P))

    print("Failed to recover flag within query limit", file=sys.stderr)
    sock.close()


if __name__ == "__main__":
    main()
