# amateursCTF – Crypto: addition 2

## Challenge Summary

We are given a remote service that prints an RSA modulus `n` and exponent `e = 3`, then repeatedly:

1. Takes a secret flag of 72 bytes.
2. Converts it to an integer and appends 256 random bits on the right.
3. Asks us for an integer `scramble`.
4. Adds `scramble` to each precomputed message.
5. Picks one of those messages at random, cubes it modulo `n`, and sends us the ciphertext.

Relevant server code (`chall.py`):

```python
from Crypto.Util.number import *
from random import getrandbits, choice

flag = open('flag.txt','rb').read().strip()
assert len(flag) == 72
flag = bytes_to_long(flag) << 256

n = getPrime(1024) * getPrime(1024)
e = 3

print(f'{n, e = }')

while True:
    cs = [flag + getrandbits(256) for _ in range(100000)]
    scramble = int(input('scramble the flag: '))

    ms = [(m + scramble) % n for m in cs]

    print('scrambling...')

    c = choice([pow(m, e, n) for m in ms])
    print(f'{c = }')
```

Our goal is to recover the flag.

## Understanding the Scheme

- Let `F` be the 72‑byte flag as an integer.
- The server computes `F_shift = F << 256`, i.e. it appends 256 zero bits.
- For each loop, it creates 100000 messages of the form
  - `M_i = F_shift + r_i`, where each `r_i` is a fresh 256‑bit random integer.
- After we send `scramble`, each message becomes
  - `M_i' = (M_i + scramble) % n`.
- One random `M_i'` is chosen, and the server outputs
  - `C_i = (M_i')^3 mod n`.

In the intended solve we simply fix `scramble = 0`, so `M_i' = M_i = F_shift + r_i`.

Important size facts:

- `n` is a 2048‑bit RSA modulus (product of two 1024‑bit primes).
- `F_shift` has about 576 + 256 = 832 bits.
- Each `r_i` is 256 bits.
- So each plaintext `M_i` is about 832 bits, much smaller than `n` (≈ 2048 bits), but **not** small enough to just cube‑root the ciphertexts.

The service lets us query as many ciphertexts as we want, all of the form:

> `C_i = (F_shift + r_i)^3 mod n`

for fresh random `r_i`.

## Key Idea: Look at Differences of Ciphertexts

Take two plaintexts:

- `m_0 = F_shift + r_0`
- `m_k = F_shift + r_k`

and their ciphertexts:

- `c_0 = m_0^3 mod n`
- `c_k = m_k^3 mod n`

Consider the *difference of ciphertexts modulo `n`*:

```text
Δ_k = (c_k - c_0) mod n
```

As integers we actually have:

```text
m_k^3 = q_k n + c_k
m_0^3 = q_0 n + c_0
=> m_k^3 - m_0^3 = (q_k - q_0) n + (c_k - c_0)
```

Because `m_i` are only ~832 bits, while `n` is ~2048 bits, the **actual difference**

```text
|m_k^3 - m_0^3| < n
```

so when we take `(c_k - c_0) mod n` and then reduce to the signed interval `[-n/2, n/2]`, we recover the *true* integer difference:

```text
diff_k = m_k^3 - m_0^3   (as integers, not just mod n)
```

Now use the algebra identity:

```text
a^3 - b^3 = (a - b)(a^2 + ab + b^2)
```

With `a = m_k`, `b = m_0`, this gives:

```text
diff_k = (m_k - m_0) * (m_k^2 + m_k m_0 + m_0^2)
```

Define:

- `q_k = m_k - m_0 = r_k - r_0` (difference of the random 256‑bit parts).
- `Q_k = m_k^2 + m_k m_0 + m_0^2`.

Then:

```text
diff_k = q_k * Q_k.
```

### Why Ratios of Differences Are Useful

Since `F_shift` dominates `r_i` (it’s much larger), we have:

```text
m_k ≈ m_0 ≈ F_shift
=> Q_k ≈ 3 * F_shift^2
```

So for different `k`, the `Q_k`’s are all *very close* to each other. This means:

```text
diff_k / diff_j = (q_k Q_k) / (q_j Q_j)
             ≈   (q_k / q_j)
```

The right-hand side is a ratio of *small integers* (`q_k`, `q_j` are differences of 256‑bit random values), so it is a rational number with a relatively small denominator.

Hence, from many ratios of the form `diff_k / diff_ref`, we can try to reconstruct the structure of these `q_k`’s using rational approximation.

## Recovering a Plaintext Difference

The core trick in the solve script is: if we manage to learn **one actual difference of plaintexts**

```text
q1 = m_ref - m_0
```

then from the known `diff_ref = m_ref^3 - m_0^3` we can algebraically recover `m_0` itself.

Assume we already know such a `q1`. Then:

```text
diff_ref = m_ref^3 - m_0^3
         = (m_ref - m_0)(m_ref^2 + m_ref m_0 + m_0^2)
         = q1 * S
```

where

```text
S = m_ref^2 + m_ref m_0 + m_0^2.
```

So we can compute:

```python
s_val = diff_ref // q1  # this is S
```

We now want to solve for `m_0` from `q1` and `S`.

Note that `m_ref = m_0 + q1`. Plug into `S`:

```text
S = (m_0 + q1)^2 + (m_0 + q1)m_0 + m_0^2
  = m_0^2 + 2 m_0 q1 + q1^2 + m_0^2 + m_0 q1 + m_0^2
  = 3 m_0^2 + 3 m_0 q1 + q1^2
```

Now compute:

```text
inside = 4*S - q1^2
       = 4(3 m_0^2 + 3 m_0 q1 + q1^2) - q1^2
       = 12 m_0^2 + 12 m_0 q1 + 3 q1^2
       = 3(4 m_0^2 + 4 m_0 q1 + q1^2)
       = 3(2 m_0 + q1)^2
```

So:

```text
inside / 3 = (2 m_0 + q1)^2
```

This tells us that `inside / 3` is a perfect square. Let:

```text
sqrt_val = sqrt(inside / 3) = 2 m_0 + q1
```

Then we can solve for `m_0`:

```text
2 m_0 = sqrt_val - q1
=> m_0 = (sqrt_val - q1) / 2
```

This is *exactly* what the solve script does:

1. Compute `inside = 4*s_val - q1*q1`.
2. Check that `inside % 3 == 0`.
3. Let `inside //= 3`.
4. Check that `inside` is a perfect square and take the integer square root `sqrt_val`.
5. Try both signs in `numer = -q1 ± sqrt_val`.
6. When `numer` is even, set `m0 = numer // 2`.
7. Verify that `pow(m0, 3, n) == ciphertexts[0]` to confirm.

If everything matches, we have recovered the first plaintext `m0` (which equals `F_shift + r_0`).

## How to Get `q1` from Ciphertext Differences

The main remaining question is: how do we get an actual plaintext difference `q1`?

Recall:

```text
diff_k = (m_k^3 - m_0^3) = q_k * Q_k
diff_ref = (m_ref^3 - m_0^3) = q_ref * Q_ref
```

and each `q_k = m_k - m_0` is a random ~256‑bit integer, while `Q_k ≈ 3 F_shift^2` are all very close to each other.

So:

```text
diff_k / diff_ref = (q_k Q_k) / (q_ref Q_ref)
                 ≈ q_k / q_ref
```

This means that each ratio `diff_k / diff_ref` is extremely close to a rational number with denominator `q_ref` (or a divisor of it).

In the solve script, for each pair of ciphertext differences it:

1. Takes the reference difference `ref_diff`.
2. For all other non‑zero `diff` values, computes:

   ```python
   frac = Fraction(diff, ref_diff).limit_denominator(MAX_DENOMINATOR)
   ```

   This finds a rational approximation `num/den` of the ratio with a bounded denominator. Under the above heuristic, many of these denominators are small factors of `q_ref`.

3. Takes the **LCM of all denominators** to reconstruct a candidate value `q1` that (up to sign) should be equal to `q_ref = m_ref - m_0`.

4. Checks that `ref_diff % q1 == 0` (so `q1` really divides the difference of cubes).

5. If it passes all algebraic checks and leads to a valid `m0` that satisfies `pow(m0, 3, n) == ciphertexts[0]`, we accept this `m0`.

This works because `F_shift` is so much larger than the random 256‑bit noise that `Q_k` are essentially constant, and the continued‑fraction rational approximation is strong enough to recover `q_ref` from ratios of large integers.

## Extracting the Flag from `m0`

Once `m0` is known, we know:

```text
m0 = F_shift + r_0
```

where:

- `F_shift = F << 256`
- `r_0` is a 256‑bit random value.

So:

```python
RANDOM_BITS = 256
noise_mask = (1 << RANDOM_BITS) - 1
flag_shifted = m0 - (m0 & noise_mask)
F_int = flag_shifted >> RANDOM_BITS
flag_bytes = F_int.to_bytes(72, 'big')
```

That is:

1. Zero out the lowest 256 bits of `m0` to remove the random noise.
2. Shift right by 256 bits to undo the initial `<< 256`.
3. Convert back to 72 bytes and decode as ASCII.

This recovers the flag.

## Final Exploit Script (Conceptual)

In short, the solve script does:

1. Connect to the remote server.
2. Read `(n, e)` from the first line.
3. Repeatedly:
   - Send `scramble = 0`.
   - Read the resulting ciphertext `c`.
   - Store it.
4. Once enough ciphertexts are collected, try to recover `m0` using the `recover_m0` procedure described above (ciphertext differences + rational reconstruction + algebra).
5. Strip off the 256 random bits and decode the remaining 72 bytes as the flag.

Running this on the live instance yields:

```text
amateursCTF{n0_th3_fl4g_1s_n0T_th3_Same_1f_y0U_w3r3_w0ndeRing_533e72a10}
```

## Takeaways

- Even when RSA is used with a large exponent (`e = 3`) and the plaintext is padded with randomness, structured relationships between plaintexts can leak information.
- Here the flag was placed in the *upper* bits and randomness in the *lower* bits. This made differences of cubes strongly correlated and allowed recovery of small plaintext differences via rational approximation.
- Once any difference `m_ref - m_0` is known, the difference‑of‑cubes factorization lets you solve a simple quadratic to recover the underlying plaintexts.

