# addition Crypto Challenge – Writeup

## Challenge Overview

Files provided:

- `chall.py` – server / encryption script
- Hidden `flag.txt`

Remote instance:

- `nc amt.rs 43433`

When you connect, the server prints:

```text
n, e = (<big integer n>, 3)
scramble the flag:
```

Then it repeatedly asks you for an integer “scramble” and responds with one RSA ciphertext.

The goal is to recover the flag.

---

## Scheme Details

Relevant parts of `chall.py`:

```python
flag = open('flag.txt','rb').read().strip()
assert len(flag) == 72
flag = bytes_to_long(flag) << 256

n = getPrime(1024) * getPrime(1024)
e = 3

cs = [flag + getrandbits(256) for _ in range(100000)]
```

So:

- Let `F = bytes_to_long(flag) << 256`.
- The server creates 100000 values
  \[
    c_i = F + r_i,
  \]
  where each `r_i` is a fresh 256‑bit random integer.

For each query:

```python
scramble = int(input('scramble the flag: '))

ms = [(m + scramble)%n for m in cs]

print('scrambling...')

c = choice([pow(m, e, n) for m in ms])
print(f'{c = }')
```

Call the scramble `s`. Then:

1. For each `i`, the server computes
   \[
     m_i = (c_i + s) \bmod n.
   \]
2. It chooses a random index `i` and returns
   \[
     c = m_i^3 \bmod n.
   \]

We know `n` and `e = 3`, but we never see `c_i` or `m_i`. The flag hides inside:

\[
  c_i = F + r_i = \text{flag} \cdot 2^{256} + r_i,
\]

so once we learn any `c_i` exactly, we can recover the flag by chopping off the low 256 bits.

---

## Turning Oracle Answers into Polynomials

Fix one query with scramble `s` and response `c`. Define a polynomial over `ℤ_n[x]`:

\[
  P_s(X) = (X + s)^3 - c \pmod{n}.
\]

For that query, the (unknown) value `X = c_i` used by the server satisfies:

\[
  P_s(c_i) = (c_i + s)^3 - c_i^3 \equiv 0 \pmod{n}
\]

only when `c = (c_i + s)^3 mod n`. This is exactly how `c` was produced, so for that particular query we have:

\[
  P_s(c_i) \equiv 0 \pmod{n}.
\]

Now consider two queries that happened to use the **same** index `i`:

- First query: scramble `s₁`, ciphertext `c₁`.
- Second query: scramble `s₂`, ciphertext `c₂`.

Then `c_i` is a common root of the two polynomials:

\[
  P_{s_1}(c_i) \equiv 0 \pmod{n},\quad P_{s_2}(c_i) \equiv 0 \pmod{n}.
\]

Thus in `ℤ_n[x]`:

- `gcd(P_{s_1}, P_{s_2})` must contain the factor `(X - c_i)`.
- Since both polynomials are degree 3, the gcd will typically be exactly this linear factor (up to a unit), i.e.
  \[
    G(X) = a_1 X + a_0 \pmod{n}.
  \]

The root is then:

\[
  c_i \equiv -a_0 \cdot a_1^{-1} \pmod{n}.
\]

Because in the real challenge `c_i < n`, this congruence uniquely determines `c_i`.

So the plan is:

1. Collect enough samples `(s, c)`.
2. For each pair of samples, compute `G = gcd(P_{s_1}, P_{s_2})` in `ℤ_n[x]`.
3. When `deg(G) = 1`, solve for the root `c_i`.
4. Verify the root against the two original samples.
5. Extract the flag from `c_i`.

---

## Why Collisions Are Inevitable

Each query picks an index `i` uniformly from `0..99999` (100000 possibilities). After `K` queries we expect about `K² / (2·100000)` collisions (birthday paradox).

- For `K ≈ 300`, we already expect around one repeated index.
- For `K ≈ 1000`, we expect many collisions, making it very likely that some pair of queries share the same index.

Our solver just keeps querying and checking pairwise gcds until a linear gcd appears that produces a consistent root.

---

## Doing Polynomial GCD Modulo a Composite

We work with small degree polynomials (≤ 3) with coefficients modulo `n`. A polynomial is represented as a list:

- `[a0, a1, a2, a3]` for `a0 + a1 x + a2 x² + a3 x³`.

Key helper:

```python
def poly_from_shifted_cube(s, c, n):
    s %= n
    c %= n
    s2 = (s * s) % n
    s3 = (s2 * s) % n
    # (x + s)^3 - c = x^3 + 3 s x^2 + 3 s^2 x + (s^3 - c)
    return [(s3 - c) % n, (3 * s2) % n, (3 * s) % n, 1]
```

We implement polynomial long division and gcd in `ℤ_n[x]`:

- At each step, we need the inverse of the leading coefficient modulo `n`.
- Since `n` is composite, some coefficients may not be invertible. If that happens, we abort that gcd and treat it as “no common factor”.
- In practice, the polynomials we care about still give us a clean linear gcd when the same index is reused.

Once we have `G(X) = a_0 + a_1 X`, the candidate root is:

```python
root = (-a0 * pow(a1, -1, n)) % n
```

We then **verify** it against both original samples:

```python
pow((root + s1) % n, 3, n) == c1
pow((root + s2) % n, 3, n) == c2
```

If both checks pass, we have recovered a genuine `c_i`.

---

## Extracting the Flag

Once we know some `c_i = F + r_i`, where `r_i` is a 256‑bit random integer:

1. Mask off the low 256 bits:
   ```python
   F = (c_i >> 256) << 256
   ```
2. Undo the shift:
   ```python
   flag_int = F >> 256
   ```
3. Convert to bytes:
   ```python
   flag = flag_int.to_bytes(72, "big")
   ```

This yields the original 72‑byte flag.

---

## Exploit Implementation

I wrote an automated solver in `solve_addition.py`. High‑level structure:

1. Connect to the remote:
   ```python
   host = "amt.rs"
   port = 43433
   sock = socket.create_connection((host, port))
   ```
2. Read the banner, extract `n`, confirm `e = 3`.
3. Maintain a list `samples = []` of previously seen triples `(s, c, P_s)`.
4. For each new query:
   - Choose random 256‑bit scramble `s`.
   - Send `s` and read the response, parsing `c`.
   - Build `P_s` using `poly_from_shifted_cube`.
   - For each previous sample `(s2, c2, P2)`:
     - Compute `G = poly_gcd(P_s, P2, n)`.
     - If `deg(G) == 1`, extract root and verify it.
     - If verified, derive the flag and stop.
   - Append the new sample to `samples`.

Running it:

```bash
python3 solve_addition.py
```

The solver quickly recovers a `c_i` and prints the flag:

```text
Parsed n bits: 2048
Recovered cs = 1089925849845859491406878630224375387701894226452791505...
b'amateursCTF{1_h0p3_you_didnT_qU3ry_Th3_s3RVer_100k_tim3s_1b9490c255fe83}'
```

Final flag:

```text
amateursCTF{1_h0p3_you_didnT_qU3ry_Th3_s3RVer_100k_tim3s_1b9490c255fe83}
```

---

## Summary

- The server prepares 100000 related secrets `c_i = flag·2²⁵⁶ + r_i`.
- Each query hides some `c_i` behind a cubic shift `(c_i + s)^3 mod n`.
- When the same index is reused, the corresponding polynomials share a common root.
- Computing `gcd` of the two polynomials in `ℤ_n[x]` reveals a linear factor `(x - c_i)`.
- From this `c_i`, we strip off 256 random bits and recover the flag. 

