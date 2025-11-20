## Floor is Lava – Write‑up

### Overview

Given file: `chal` (64‑bit, PIE, stripped).

`strings chal` shows:
- Messages: `you fell into lava`, `you made it across!`, `here's your reward:`
- Flag format string: `amateursCTF{%s}`

So the binary takes some input, decides if you “made it across”, then prints the flag by formatting a secret string into `amateursCTF{%s}`.

---

### High‑level behaviour

Disassembling (`objdump -d -M intel chal`) shows the main logic starting around `0x11e9`.

Key observations:

1. The program reads **single characters** in a loop using `getchar`.
2. It ignores newlines and only accepts `w`, `a`, `s`, `d`.
3. For each valid char, it:
   - Adjusts two counters in `.bss` (treated as `x` and `y` in a grid, both modulo 8).
   - Updates a table in memory at `0x4038`/`0x4060` with a byte representing the move.
4. It does this for **0x1b = 27** iterations (see the loop with `cmp [rbp-0x20], 0x1b`).

After collecting the 27 moves, it:

1. Builds an 8×8 bitmask (rows stored as bytes) in memory around `0x4060`.  
   - Each move toggles exactly one bit in that mask.
2. Seeds `srand` with a deterministic value derived from the mask, then:
   - For `i = 0..7`:
     - Seed = `i * 0x1337 - 0x21524111`
     - Call `rand()`, take the low byte.
     - Compare with the `i`‑th row of the mask.
   - If any byte differs, it prints `you fell into lava` and exits.

If all 8 rows match this target pattern, it:

1. Computes a new seed from a 64‑bit combination of the rows.
2. Calls `rand()` 0x14 (=20) times, each time xoring a byte array at `0x4020`.
3. Finally prints:
   - `you made it across!`
   - `here's your reward:`
   - `amateursCTF{%s}` where `%s` is the decoded data at `0x4020`.

This means:
- The correct sequence of 27 `w/a/s/d` moves produces a specific 8×8 pattern of bits.
- That pattern is used both for validation and as a key to decrypt the final flag.

---

### Recovering the target pattern

We can reconstruct the target 8‑byte pattern directly from the code instead of brute forcing.

At `0x136f`–`0x13c4`:

```asm
mov eax, [rbp-0x1c]       ; i
imul eax, eax, 0x1337
sub eax, 0x21524111       ; seed
call srand
call rand
movzx edx, al             ; low 8 bits of rand()
...
movzx eax, BYTE PTR [rax+rcx*1]  ; row[i] from 0x4010
cmp edx, eax
```

Instead of reversing everything by hand, we duplicated this logic in a helper C program:

```c
for (int i = 0; i < 8; i++) {
    unsigned int seed = (unsigned int)(i * 0x1337u - 0x21524111u);
    srand(seed);
    int r = rand();
    unsigned char b = (unsigned char)r;
    printf("row %d: byte=0x%02x\n", i, b);
}
```

Running this gives the 8 target bytes:

- `[0xe1, 0xe7, 0xa2, 0xd1, 0xb6, 0xe1, 0xca, 0xc4]`

The initial rows (before any input) are stored in `.data` at `0x4010`:

- `[0x8b, 0xc9, 0x92, 0x08, 0xf9, 0x91, 0xd6, 0xc8]`

The difference between desired and initial rows is simply XOR:

```text
mask[i] = init_rows[i] ^ target_rows[i]
mask = [0x6a, 0x2e, 0x30, 0xd9, 0x4f, 0x70, 0x1c, 0x0c]
```

In other words, the player’s moves must toggle exactly the bits set in this mask.

---

### Interpreting the moves as a grid

The program treats the grid as 8×8 with torus wrapping (mod 8).

From the disassembly:
- `w`: y = (y - 1) & 7
- `s`: y = (y + 1) & 7
- `a`: x = (x - 1) & 7
- `d`: x = (x + 1) & 7

On each move, it does:

```c
rows[y] ^= (1 << x);
```

So:
- `rows[y]` is the row byte for y‑coordinate `y`.
- Bit `x` of that row is toggled each time we step on cell `(x,y)`.

The target mask tells us exactly which cells must be toggled an odd number of times:

```text
mask bytes -> set bits -> safe cells
0x6a -> bits 1,3,5,6 -> (1,0),(3,0),(5,0),(6,0)
0x2e -> bits 1,2,3,5 -> (1,1),(2,1),(3,1),(5,1)
0x30 -> bits 4,5     -> (4,2),(5,2)
0xd9 -> bits 0,3,4,6,7 -> (0,3),(3,3),(4,3),(6,3),(7,3)
0x4f -> bits 0,1,2,3,6 -> (0,4),(1,4),(2,4),(3,4),(6,4)
0x70 -> bits 4,5,6   -> (4,5),(5,5),(6,5)
0x1c -> bits 2,3,4   -> (2,6),(3,6),(4,6)
0x0c -> bits 2,3     -> (2,7),(3,7)
```

There are 28 such cells. The code reads 27 moves; the starting cell `(0,0)` is not toggled until the first move, so the path visits 28 cells total (start + 27 moves).

The puzzle is: **find a path on this 8×8 torus grid starting at `(0,0)` such that the sequence of visited cells is exactly this set of 28 “safe” cells, each visited an odd number of times, and only moving with `w/a/s/d`.**

---

### Solving the path

We model the grid in Python:

1. Build the set of required “safe” cells from the mask.
2. Build the adjacency graph of safe cells (neighbors with Manhattan distance 1 on torus).
3. Perform a DFS to search for a Hamiltonian path through all 28 safe cells, starting from the first cell reached after an initial move from `(0,0)`.

Using a small DFS with heuristics (try lower‑degree neighbors first) we quickly get a valid path:

```text
[(1,0), (1,1), (2,1), (3,1), (3,0), (3,7), (2,7), (2,6),
 (3,6), (4,6), (4,5), (5,5), (6,5), (6,4), (6,3), (7,3),
 (0,3), (0,4), (1,4), (2,4), (3,4), (3,3), (4,3), (4,2),
 (5,2), (5,1), (5,0), (6,0)]
```

We then convert this path back into movement directions `w/a/s/d` starting from `(0,0)`:

- Move from current `(x,y)` to next `(nx,ny)`:
  - if `(nx,ny) == ((x+1)&7, y)` → `d`
  - if `(nx,ny) == ((x-1)&7, y)` → `a`
  - if `(nx,ny) == (x, (y+1)&7)` → `s`
  - if `(nx,ny) == (x, (y-1)&7)` → `w`

This yields the input string:

```text
dsddwwawddwddwwddsdddwdwdwwd
```

Simulating these moves in Python (using the exact same rules) confirms that they transform the initial rows to the target rows:

```text
final rows: [0xe1, 0xe7, 0xa2, 0xd1, 0xb6, 0xe1, 0xca, 0xc4]
match? True
```

---

### Getting the flag

Finally, we feed the discovered move sequence to the challenge binary:

```sh
echo 'dsddwwawddwddwwddsdddwdwdwwd' | ./chal
```

Program output:

```text
> > > > > > > > > > > > > > > > > > > > you made it across!
here's your reward:
amateursCTF{l4va_r3v_05f0d4ff51fb}
```

**Flag:** `amateursCTF{l4va_r3v_05f0d4ff51fb}`

