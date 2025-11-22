# Rewrite It In Zig – Writeup

## Challenge overview

- Category: pwn
- Files: `chal` (binary), `chal.zig` (source)
- Remote: `amt.rs:27193`

When we run the binary it prints a short message and then waits for input:

```zig
const std = @import("std");
const print = std.debug.print;

pub fn main() void {
    print("you can never have too much zig pwn.\n", .{});

    var backing: [0x100]u8 = undefined;
    var buf: []u8 = &backing;
    buf.len = 0x1000;
    _ = std.io.getStdIn().read(buf) catch {};
}
```

The whole challenge is in these few lines.

## Bug analysis

- `backing` is a fixed stack buffer of size `0x100` (256) bytes.
- `buf` is a slice that initially points to `backing`.
- The important bug: `buf.len = 0x1000;` makes the slice claim it is **4096 bytes long**, even though the underlying storage is still only 256 bytes.
- The program then calls `read(buf)`, which means it may read up to `0x1000` bytes into a 0x100‑byte stack buffer.

This is a classic **stack-based buffer overflow**. By sending a long enough line of input, we can:

- Overwrite saved registers on the stack, including the saved return address (RIP).
- Place our own data after the saved RIP to control the stack layout when execution returns.

Because the binary is statically linked and stripped, using normal ret2libc is inconvenient. Instead, we use **SROP (Sigreturn Oriented Programming)**.

## High-level exploit idea (SROP)

On Linux x86‑64, the `rt_sigreturn` system call (number 15) allows the kernel to restore **all** CPU registers from a user‑supplied structure on the stack, called a `sigcontext`. Pwntools wraps this as `SigreturnFrame`.

Basic SROP pattern:

1. Find a gadget to set `rax = 15` (the syscall number for `rt_sigreturn`).
2. Jump to a `syscall` instruction.
3. The kernel reads a `sigcontext` structure from the stack and restores all registers (RIP, RSP, RDI, RSI, RDX, etc.).
4. After this, we fully control the CPU state.

In this binary we use:

- `0x00000000010c5cc4` – a gadget acting like `pop rax ; ret`.
- `0x0000000001038e9a` – a `syscall` gadget.
- Writable memory around `0x00000000010d8100` and `0x00000000010d9000` (used like a `.bss` region).

We will build a two‑stage SROP chain:

1. **Stage 1**: Use SROP to call `read(0, bss, 0x200)` to load stage 2 into memory and pivot the stack there.
2. **Stage 2**: Use SROP again to call `execve("/bin/sh", NULL, NULL)` to spawn a shell.

Once we have a shell on the remote server, we can simply `cat flag`.

## Finding the overflow offset

We can use pwntools’ `cyclic()` / `cyclic_find()` or any other pattern method to find how many bytes are needed to overwrite RIP.

For this challenge, the correct offset is **360 bytes**. That means:

- The first 360 bytes fill the stack buffer and some saved registers.
- The 361st–368th bytes overwrite the saved RIP with our gadget address.

## Building stage 1: SROP `read`

We first connect to the remote and build a `SigreturnFrame` that will perform a `read` system call:

- `rax = 0` → syscall number for `read`.
- `rdi = 0` → file descriptor 0 (stdin).
- `rsi = 0x00000000010d8100` → where to store the second stage payload.
- `rdx = 0x200` → how many bytes to read.
- `rip = 0x0000000001038e9a` → `syscall` gadget.
- `rsp = 0x00000000010d8100 - 48 + 8` → pivot the stack near our buffer in writable memory.

To reach this frame, we first need to trigger `rt_sigreturn`:

- Use `pop rax ; ret` at `0x00000000010c5cc4` to set `rax = 15`.
- Then call the `syscall` gadget at `0x0000000001038e9a`.
- The kernel sees `rax = 15` and performs `rt_sigreturn`, restoring registers from the `SigreturnFrame` we place on the stack after RIP.

So the first payload is:

- `b"A"*360` – fill the buffer up to saved RIP.
- `p64(0x00000000010c5cc4)` – overwrite RIP with `pop rax ; ret`.
- `p64(0xf)` – value for `rax` (15 = `rt_sigreturn`).
- `p64(0x0000000001038e9a)` – `syscall` gadget.
- `bytes(frame)` – serialized `SigreturnFrame` for `read`.
- `b"B"*8` – small padding.

This causes the program to:

1. Return into `pop rax ; ret`, putting 15 into `rax`.
2. Execute the `syscall` gadget.
3. The kernel does `rt_sigreturn` and loads our frame.
4. The CPU now executes `read(0, 0x10d8100, 0x200)` with `RSP` moved into our chosen writable region.
5. The program blocks, waiting for more data from us – this will be our second stage.

## Building stage 2: SROP `execve("/bin/sh")`

For the second stage we want to call:

```c
execve("/bin/sh", NULL, NULL);
```

That is:

- `rax = 59` → syscall number for `execve`.
- `rdi = address_of("/bin/sh")`.
- `rsi = 0`.
- `rdx = 0`.
- `rip = syscall_gadget`.

We also place the string `/bin/sh\x00` at the same `bss` address we used for `rsi` in the first stage.

Again we trigger `rt_sigreturn` the same way:

- Send another small ROP stub: `pop rax ; ret` → `rax = 15` → `syscall` → `rt_sigreturn`.
- After that stub, we place a new `SigreturnFrame` that performs the `execve` syscall.

So the second payload is:

- `/bin/sh\x00` – the command string at `0x10d8100`.
- `p64(0x00000000010c5cc4)` – `pop rax ; ret`.
- `p64(0xf)` – 15 = `rt_sigreturn`.
- `p64(0x0000000001038e9a)` – `syscall` gadget.
- `bytes(frame2)` – second `SigreturnFrame` with `rax = 59`, `rdi` pointing to `/bin/sh`, etc.

After `rt_sigreturn` restores this frame, the kernel executes `execve("/bin/sh", NULL, NULL)` and we get a shell.

Running this exploit against the remote service gives a shell, and then:

```sh
cat flag
```

returns:

```text
amateursCTF{i_love_zig_its_my_favorite_language_and_you_will_never_escape_the_zig_pwn_ahahaha}
```

## Summary

- The Zig program corrupts a stack buffer length, allowing a large overflow.
- We use that overflow to control RIP and place a `SigreturnFrame` on the stack.
- With SROP we first call `read` to load a second stage, then `execve("/bin/sh")`.
- With the resulting shell we read the flag from the remote server.

