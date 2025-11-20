# aescure – Write-up (AmateursCTF)

## Challenge Overview

We are given the following Python snippet:

```python
from Crypto.Cipher import AES

cipher = AES.new(open('flag.txt', 'rb').read(), AES.MODE_ECB)
pt = b'\x00' * 16
print(cipher.encrypt(pt).hex())
```

and the corresponding output:

```text
5aed095b21675ec4ceb770994289f72b
```

The task is to recover the flag, which is stored in `flag.txt`.

## What the Code Does

- The contents of `flag.txt` are read as raw bytes.
- Those bytes are used directly as the AES key.
- AES is used in ECB mode.
- The plaintext is 16 zero bytes: `b"\x00" * 16`.
- The script prints `AES_key(0^16)` as a hex string.

So we effectively know a single AES encryption:

> `AES_key(0x00000000000000000000000000000000) = 0x5aed095b21675ec4ceb770994289f72b`

The unknown is the AES key, which is exactly the content of `flag.txt`.

## Initial Observations

- AES-ECB with an unknown key and a known plaintext–ciphertext pair is normally secure; you cannot feasibly recover an arbitrary 128‑bit key from just one pair.
- However, this is a CTF, so there must be some structure we can exploit.
- We are told (or can infer from the CTF style) that the flag has the form:

  ```text
  amateursCTF{...}
  ```

- AES keys must be 16, 24, or 32 bytes long (AES‑128/192/256). The most natural assumption is that the whole flag is exactly 16 bytes long, i.e.:

  ```text
  key = flag = 16-byte ASCII string
  ```

  In other words:

  ```text
  flag = "amateursCTF{???}"
  ```

  because `"amateursCTF{"` is already 12 characters, and a 16‑byte key would mean we have 3 unknown characters plus the closing `}`:

  - 12 bytes: `amateursCTF{`
  - 3 bytes: unknown characters
  - 1 byte: `}`

  Total: 16 bytes.

That reduces the key search space from 2¹²⁸ to “all combinations of 3 characters from some small alphabet”.

## Attack Idea

1. Assume the key is exactly the flag: `key = flag`.
2. Assume the flag format is `amateursCTF{???}` (3 unknown characters, then `}`).
3. Choose a reasonable alphabet for the 3 unknown characters:
   - First try lowercase letters, digits, and `_`/`}`.
   - If that fails, widen to all printable (non‑whitespace) ASCII characters.
4. For each candidate flag:
   - Use it as the AES key.
   - Compute `AES_key(0^16)` in ECB mode.
   - Compare the result with the given ciphertext `5aed095b21675ec4ceb770994289f72b`.
5. When they match, we have found the correct key and hence the flag.

Because 3 characters from a printable set (≈94 characters) gives at most 94³ ≈ 830k possibilities, this brute force is very fast.

## Attack Script

Below is the script used to perform the brute force (using PyCryptodome’s `Crypto.Cipher.AES`):

```python
from Crypto.Cipher import AES
from itertools import product
import string

cipher_hex = '5aed095b21675ec4ceb770994289f72b'
ct = bytes.fromhex(cipher_hex)
pt = b'\x00' * 16

prefix = 'amateursCTF{'

# Use all printable, non-whitespace ASCII characters
chars = ''.join(ch for ch in string.printable if ch not in string.whitespace)
print('Trying charset size:', len(chars))

for a, b, c in product(chars, repeat=3):
    inner = a + b + c
    key_str = prefix + inner + '}'

    # Ensure 16-byte key
    if len(key_str) != 16:
        continue

    key = key_str.encode()
    test_ct = AES.new(key, AES.MODE_ECB).encrypt(pt)

    if test_ct == ct:
        print('FOUND FLAG:', key_str)
        break
```

## Result

Running the script finds:

```text
FOUND FLAG: amateursCTF{@3s}
```

We can double‑check by encrypting 16 zero bytes with this key and confirming the ciphertext:

```python
from Crypto.Cipher import AES

key = b"amateursCTF{@3s}"
pt = b"\x00" * 16
ct = AES.new(key, AES.MODE_ECB).encrypt(pt)
print(ct.hex())
```

Output:

```text
5aed095b21675ec4ceb770994289f72b
```

which matches the given ciphertext exactly.

## Flag

The recovered flag is:

```text
amateursCTF{@3s}
```

