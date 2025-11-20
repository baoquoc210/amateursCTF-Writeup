# amateursCTF 2025 – Writeups

This repository contains our solutions and writeups for **amateursCTF 2025**.  
We played as a team and finished in the **top 25**, and this repo collects the notes, exploit scripts, and auxiliary files we used during the CTF.

Most challenges live in their own subdirectory under `Crypto`, `Pwn`, `Rev`, `Web`, or `misc`, often along with a corresponding writeup.

---

## Crypto

- **addition** – RSA `e = 3` with noisy additions and a polynomial GCD attack  
  - Writeup: [`Crypto/addition/WRITEUP.md`](Crypto/addition/WRITEUP.md)
- **addition 2** – hardened version of *addition* that requires a bivariate small-root (Coppersmith + LLL) attack  
  - Writeup: [`Crypto/addition 2/WRITEUP.md`](Crypto/addition%202/WRITEUP.md)
- **aescure** – recover an AES key when the key *is* the flag and the flag format is known  
  - Writeup: [`Crypto/aescure/writeup.md`](Crypto/aescure/writeup.md)
- **division** – number theory / modular arithmetic challenge  
  - Writeup: [`Crypto/division/WRITEUP.md`](Crypto/division/WRITEUP.md)
- **uncrackable** – stream cipher / PRNG analysis and key recovery  
  - Writeup: [`Crypto/uncrackable/WRITEUP.md`](Crypto/uncrackable/WRITEUP.md)

---

## Pwn

- **Easy Bof** – classic stack buffer overflow with a `win()` function and ROP  
  - Writeup: [`Pwn/Easy Bof/WRITEUP.md`](Pwn/Easy%20Bof/WRITEUP.md)
- **Easy Heap** – small heap challenge with tcache poisoning and safe-linking bypass to smash a global check buffer and pop a shell  
  - Writeup: [`Pwn/Easy Heap/WRITEUP.md`](Pwn/Easy%20Heap/WRITEUP.md)
- **Rewrite It In Zig** – reversing and exploiting a Zig binary  
  - Writeup: [`Pwn/Rewrite It In Zig/writeup.md`](Pwn/Rewrite%20It%20In%20Zig/writeup.md)

---

## Reverse Engineering

- **floor-is-lava** – arithmetic / control-flow reversing puzzle  
  - Writeup: [`Rev/floor-is-lava/WRITEUP.md`](Rev/floor-is-lava/WRITEUP.md)
- **functioning** – heavily obfuscated JavaScript / Node challenge  
  - Writeup: [`Rev/functioning/WRITEUP.md`](Rev/functioning/WRITEUP.md)
- **normal-java-code** – reversing a Java program and decompiling the logic  
  - Writeup: [`Rev/normal-java-code/WRITEUP.md`](Rev/normal-java-code/WRITEUP.md)
- **wasm-checker** – WebAssembly reversing with `wasm2wat` and manual analysis  
  - Writeup: [`Rev/wasm-checker/WRITEUP.md`](Rev/wasm-checker/WRITEUP.md)

---

## Web

- **desafe** – deserialization and logic bugs in a small web service  
  - Writeup: [`Web/desafe/WRITEUP.md`](Web/desafe/WRITEUP.md)
- **hCAPTCHA** – bypassing a CAPTCHA-like verification flow and exploiting the verifier  
  - Writeup: [`Web/hCAPTCHA/WRITEUP.md`](Web/hCAPTCHA/WRITEUP.md)

---

## Misc

- **Snake** – shell / logic challenge abusing quoting and file paths to reach a SUID helper  
  - Writeup: [`misc/Snake/writeup.md`](misc/Snake/writeup.md)
- **Uwa so Piano – megalovania_snippet** – musical / MIDI-based challenge around recognizing and reconstructing a familiar tune  
  - Writeup: [`misc/Uwa so Piano/megalovania_snippet/WRITEUP.md`](misc/Uwa%20so%20Piano/megalovania_snippet/WRITEUP.md)

---

## Notes

- Many directories also include solver scripts (`solve.py`, Sage scripts, etc.) and Dockerfiles used to reproduce or practice the challenges locally.
- File and directory names with spaces are kept as in the original CTF infrastructure; GitHub links here use URL-encoded spaces (e.g. `%20`).

