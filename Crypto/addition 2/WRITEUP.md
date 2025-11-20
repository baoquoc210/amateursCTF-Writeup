# addition 2 – Crypto Challenge Write-up (amateursCTF 2025)

## Challenge Overview

Files provided:

- `chall.py` – server / encryption script (variant of the original **addition** challenge)
- Hidden `flag.txt`

Remote instance (during the CTF):

- `nc amt.rs <port>`

The server prints `n, e` once and then runs an infinite loop:

```python
flag = open('flag.txt','rb').read().strip()
assert len(flag) == 72
flag = bytes_to_long(flag) << 256

n = getPrime(1024) * getPrime(1024)
e = 3

print(f'{n, e = }')

while True:
    cs = [flag + getrandbits(256) for _ in range(100000)]
    scramble = int(input('scramble the flag: '))

    ms = [(m + scramble)%n for m in cs]

    print('scrambling...')

    c = choice([pow(m, e, n) for m in ms])
    print(f'{c = }')
```

The goal is to recover the 72‑byte flag.

Compared to the original **addition** challenge:

- `cs` is **re-generated on every query** instead of being fixed.
- This kills the “same index twice” collision trick and the univariate polynomial GCD approach from the first challenge.

We only really get a **single sample** of the form:

```text
c ≡ (flag << 256 + r + s)^3 (mod n)
```

where:

- `flag << 256` means the flag sits in the *high* bits and the low 256 bits are 0.
- `r` is a fresh random 256‑bit integer.
- `s` is the scramble we chose for that query.

---

## Structure of the Scheme

Let:

- `F = bytes_to_long(flag)` (unknown, but 72 bytes, so about 576 bits),
- `M = (F << 256) + r + s`, with `0 ≤ r < 2^256`, and `s` chosen by us,
- `n` a 2048‑bit RSA modulus, and `e = 3`.

For any fixed query (we only need one in practice), we have:

```text
M^3 ≡ c (mod n)
```

So there exist integers `r` and `k` such that the **exact** relation holds:

```text
M^3 - c - k·n = 0
```

with:

- `M = (F << 256) + r + s`,
- `r` is a 256‑bit quantity,
- `k` is roughly of size `M^3 / n` (so around the size of `n`).

This can be viewed as a **bivariate polynomial equation** in two unknowns that are “small” relative to powers of `n`, which is exactly the setting for a Coppersmith‑style small‑root attack.

---

## Idea: 2D Coppersmith on a Bivariate Polynomial

We can rearrange the equation into the form:

```text
f(x, y) = ((F << 256) + s + x)^3 - c - y·n = 0
```

where:

- `x` stands for the unknown noise `r` (bounded by about `2^256`),
- `y` stands for the unknown quotient `k`.

The key observation is that, thanks to the `<< 256`, the **low 256 bits of `M` are entirely controlled by `r + s`**, and `r` is genuinely small compared to the modulus.

Standard 2‑dimensional Coppersmith techniques tell us that if:

- We know a modulus `n`,
- We have a polynomial equation `f(x, y) ≡ 0 (mod n)`,
- The true solution `(x₀, y₀)` is small in both coordinates,

then we can build a lattice from multiples of `f(x, y)` and use **LLL** to recover a polynomial that actually vanishes at `(x₀, y₀)` over the integers. From that polynomial we can then extract the small root.

In our case:

- We treat `x = r` as the small root we really care about.
- The solver builds a 2D lattice basis from shifted multiples of `f(x, y)`.
- After LLL, it derives candidate polynomials, eliminates `y` via resultants, and finally looks for integer roots in `x`.

Once we recover `M = (F << 256) + r + s`, the flag is just:

```text
F = M >> 256
flag_bytes = long_to_bytes(F)
```

---

## Implementation Notes

To avoid re‑implementing 2D Coppersmith during the CTF, we packaged the solver logic into a compiled `.pyc` module and called it from a small driver:

- `Crypto/addition 2/long_solve_driver.py`:
  - Reads the captured `n` and `c` from `current_nc.txt`.
  - Loads the precompiled solver from `__pycache__/solve_addition2_bd.cpython-312.pyc`.
  - Calls `solve_from_nc_line(n_str, c_str)` to compute the flag bytes.
  - Writes the result to `flag_output.txt` and logs it.

The usage flow was:

1. Connect once to the remote service.
2. Record the printed `n` and a single `c` value into `current_nc.txt`.
3. Launch `long_solve_driver.py` in the background (it can run for a while).
4. Wait for it to finish; it prints something like:

   ```text
   FLAG_READY: amateursCTF{...}
   ```

5. Submit the recovered flag.

We only needed **one** ciphertext sample; the extra randomization in `cs` made the original collision‑based attack impossible, but it also gave the structure needed for this more advanced lattice attack.

---

## Takeaways

- Shifting the flag with `<< 256` creates a very strong algebraic structure: the low 256 bits are essentially pure noise, and “small” compared to the modulus.
- Even when the server re‑randomizes everything on each query, if the encryption is **deterministic RSA with small exponent**, you can often set up a small‑root problem and attack it with Coppersmith.
- 2D Coppersmith (bivariate) is powerful: it lets you treat both the random noise and the unknown quotient as variables and still recover the hidden message from a single sample.

