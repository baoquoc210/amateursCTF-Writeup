#!/usr/bin/env python3
import ast
import math
from fractions import Fraction
from typing import List

from pwn import remote

#Change to the appropriate host and port
HOST = "amt.rs"
PORT = 38531
SCRAMBLE = 0
SAMPLE_TARGET = 60
SAMPLE_INCREMENT = 20
MAX_DENOMINATOR = 1 << 280
RANDOM_BITS = 256


def signed_diff(a: int, b: int, mod: int) -> int:
    diff = (a - b) % mod
    if diff > mod // 2:
        diff -= mod
    return diff


def recv_ciphertext(io) -> int:
    io.recvuntil(b"scramble the flag: ")
    io.sendline(str(SCRAMBLE).encode())
    while True:
        line = io.recvline()
        if line.startswith(b"c ="):
            return int(line.split(b"=", 1)[1])


def collect_samples(io, count: int) -> List[int]:
    samples = []
    for _ in range(count):
        samples.append(recv_ciphertext(io))
    return samples


def recover_m0(ciphertexts: List[int], n: int) -> int:
    diffs = []
    base = ciphertexts[0]
    for idx in range(1, len(ciphertexts)):
        diff = signed_diff(ciphertexts[idx], base, n)
        if diff != 0:
            diffs.append((idx, diff))
    if len(diffs) < 2:
        raise ValueError("Need more distinct ciphertexts")

    for ref_idx, ref_diff in diffs:
        others = []
        for idx, diff in diffs:
            if idx == ref_idx:
                continue
            frac = Fraction(diff, ref_diff).limit_denominator(MAX_DENOMINATOR)
            if frac.denominator == 0:
                continue
            others.append(frac)
        if not others:
            continue

        lcm_val = abs(others[0].denominator)
        for frac in others[1:]:
            lcm_val = math.lcm(lcm_val, abs(frac.denominator))
        if lcm_val == 0:
            continue

        q1 = lcm_val if ref_diff > 0 else -lcm_val
        if ref_diff % q1 != 0:
            continue
        s_val = ref_diff // q1
        inside = 4 * s_val - q1 * q1
        if inside % 3 != 0:
            continue
        inside //= 3
        if inside <= 0:
            continue
        sqrt_val = math.isqrt(inside)
        if sqrt_val * sqrt_val != inside:
            continue
        for sign in (1, -1):
            numer = -q1 + sign * sqrt_val
            if numer % 2 != 0:
                continue
            m0 = numer // 2
            if m0 <= 0:
                continue
            if pow(m0, 3, n) == ciphertexts[0]:
                return m0
    raise ValueError("Failed to recover m0")


def main() -> None:
    io = remote(HOST, PORT)
    header = io.recvline().decode().strip()
    n = ast.literal_eval(header.split("=", 1)[1].strip())[0]

    ciphertexts = collect_samples(io, SAMPLE_TARGET)

    while True:
        try:
            m0 = recover_m0(ciphertexts, n)
            break
        except ValueError:
            ciphertexts.extend(collect_samples(io, SAMPLE_INCREMENT))

    flag_shifted = m0 - (m0 & ((1 << RANDOM_BITS) - 1))
    flag_bytes = (flag_shifted >> RANDOM_BITS).to_bytes(72, "big")
    print(flag_bytes.decode(errors="ignore"))
    io.close()


if __name__ == "__main__":
    main()

