## uncrackable Crypto Challenge – Writeup

### Challenge Overview

Given:

- `chall.py` (encryption script)
- `out.txt` (hex-encoded ciphertext)
- Hidden `flag.txt` with `len(flag) == 47`

The script:

```python
import os
import hashlib

flag = open("flag.txt", "rb").read()
assert len(flag) == 47  # just an fyi

class stream():
    def __init__(self, seed = os.urandom(8)):
        self.state = hashlib.sha256(str(seed).encode()).digest()[:len(flag)]
    
    def next(self):
        out = self.state[0]
        self.state = self.state[1:] + bytes([(out + 1) % 256])
        return out
    
    def get_bytes(self, num):
        return bytes(self.next() for _ in range(num))


def xor(a, b):
    assert len(a) == len(b)
    return bytes(i ^ j for i, j in zip(a, b))

def encrypt(x):
    return xor(x := x.strip(), rng.get_bytes(len(x)))

rng = stream()
open("out.txt", "w").write(
    b"".join(encrypt(os.urandom(2)) for _ in range(10000)).hex()
    + encrypt(flag).hex()
)
```

Goal: recover the flag from `out.txt`.

---

### Understanding the PRNG

`stream` is a custom stream cipher:

- Seed: `os.urandom(8)` → `sha256(str(seed).encode())`.
- Initial state: first `len(flag)` bytes of the digest.
  - `len(flag) = 47`, but a SHA‑256 digest is only 32 bytes.
  - Slicing with `[:len(flag)]` just gives all 32 bytes, so `state` has **length 32**.

Generation:

- `next()`:
  - Output `out = state[0]`
  - Update: `state = state[1:] + bytes([(out + 1) % 256])`
  - So on each call, we:
    - shift the 32-byte window left by one,
    - append `(previous_output + 1) mod 256` at the end.

Let `y_t` be the output of the PRNG at time `t`. Track what happens to `y_t`:

- At time `t`, we output `y_t = state_t[0]`.
- Right after, we append `(y_t + 1) mod 256` at the end of `state`.
- After 32 calls, that appended byte will have shifted all the way to the front.

Therefore:

> **Recurrence:**  
> `y_{t + 32} ≡ y_t + 1 (mod 256)`

This linear recurrence completely determines the keystream from any block of 32 consecutive outputs.

---

### Structure of the Ciphertexts

The script uses a *single* `rng` instance to encrypt:

1. 10,000 random messages:
   - Plaintext: `os.urandom(2).strip()`
   - Each plaintext is the 2‑byte random string with leading/trailing whitespace removed.
   - Length of each message is 0, 1 or 2 bytes.
   - All **remaining bytes after `strip()` are non‑whitespace**.
2. Then the 47‑byte flag.

Encryption:

- For a plaintext byte `p_t` and keystream byte `y_t`:
  - `c_t = p_t ^ y_t`

Observations about the random part:

- `os.urandom(2)` yields 2 uniform random bytes.
- `bytes.strip()` for bytes removes ASCII whitespace from both ends:
  - whitespace set: `{9, 10, 11, 12, 13, 32}` (tab, newline, carriage return, space, ...).
- For 0–2 byte strings, any whitespace can only be at the ends, so it is removed.
- Hence **all bytes that remain after `strip()` are non‑whitespace**.

So, **for every plaintext byte in the random part**:

- `p_t ∉ W`, where `W = {9, 10, 11, 12, 13, 32}`.

This constraint is the key to the attack.

---

### Mod‑32 Columns and Keystream Constraints

We know:

- `c_t = p_t ^ y_t`
- For random part: `p_t ∉ W`
- Recurrence: `y_{t} = y_k + n (mod 256)` for indices `t = k + 32·n`

Define:

- For `k ∈ {0, 1, ..., 31}`, the `k`‑th **column** consists of positions:
  - `t = k, k + 32, k + 2·32, ...` (as long as `t` is inside the random part).
- Let `y_k` be the keystream byte at position `k`.
- Then for column `k`, at row `n`:
  - `y_{k + 32n} ≡ y_k + n (mod 256)`.

For a given ciphertext byte `c_t` in the random part (`t = k + 32n`):

- We know `p_t = c_t ^ y_t = c_t ^ (y_k + n)`.
- We also know `p_t ∉ W`.

This gives **forbidden values for `y_k`**:

For any whitespace byte `w ∈ W`, if the plaintext were `w` we would have:

- `w = c_t ^ (y_k + n)`  
  ⇒ `y_k ≡ (w ^ c_t) − n (mod 256)`

But `p_t` is **not** whitespace, so `y_k` **cannot** equal these values.

Thus for each `(t, w)` we get a “banned” value of `y_k`:

- `y_k ≠ ((w ^ c_t) − n) mod 256`

Over all rows `n` in a column and all six whitespace values in `W`, we accumulate many forbidden values for `y_k`. Because there are 10,000 random messages (roughly 20,000 random bytes) spread across only 32 columns, each `y_k` gets hundreds of constraints and is **uniquely determined**.

---

### Recovering the Initial 32 Keystream Bytes

I implemented the above logic in a short Python script:

1. Load `out.txt`, hex‑decode to bytes.
2. Split into:
   - Random part: all but the last 47 bytes.
   - Flag ciphertext: last 47 bytes.
3. For each column `k = 0..31`:
   - Start with `allowed_y = {0..255}`.
   - Walk positions `t = k + 32·n` within the random area.
   - For each such `t` and each whitespace `w ∈ W`:
     - Compute `bad_y = ((w ^ c_t) − n) mod 256` and mark it as forbidden.
   - After processing all rows, the **only remaining** candidate is the real `y_k`.

Running that gave a unique solution for each `k`:

```text
Initial outputs (y_0..y_31):
[233, 181, 152, 141, 113, 52, 157, 65,
 40, 221, 57, 93, 231, 213, 40, 238,
 235, 196, 194, 9, 89, 7, 200, 148,
 196, 214, 227, 117, 225, 28, 153, 205]
```

These are the first 32 keystream bytes.

Using the recurrence `y_{t+32} = y_t + 1 (mod 256)`, we can now reconstruct **every keystream byte** used in the entire encryption (random data + flag).

---

### Decrypting the Flag

Once we know all keystream bytes:

- For every ciphertext byte `c_t` we compute `p_t = c_t ^ y_t`.
- The flag is just the last 47 bytes of the plaintext.

The script to reconstruct the keystream and decrypt:

```python
from binascii import unhexlify

ct = list(unhexlify(open("out.txt").read().strip()))
N = len(ct)
flag_len = 47
rand_len = N - flag_len

initial = [233, 181, 152, 141, 113, 52, 157, 65,
           40, 221, 57, 93, 231, 213, 40, 238,
           235, 196, 194, 9, 89, 7, 200, 148,
           196, 214, 227, 117, 225, 28, 153, 205]

# Rebuild full keystream
ks = [0] * N
for t in range(N):
    if t < 32:
        ks[t] = initial[t]
    else:
        ks[t] = (ks[t - 32] + 1) & 0xFF

pt = bytes(c ^ k for c, k in zip(ct, ks))
flag = pt[-flag_len:]
print(flag.decode())
```

Output:

```text
the_r4nd0m_data_isnT_s0_R4nd0m_hUh_8d7ac2d8e8d3
```

---

### Final Flag

```text
the_r4nd0m_data_isnT_s0_R4nd0m_hUh_8d7ac2d8e8d3
```

