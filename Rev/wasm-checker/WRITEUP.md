# amateursCTF – wasm-checker Write-up

## Challenge Overview

We are given two files:

- `main.mjs` – a small Node.js wrapper.
- `module.wasm` – a WebAssembly module exporting a single function `check`.

`main.mjs` loads the WASM, writes the user-provided flag into linear memory, and then calls `check()`:

```js
const buffer = await readFile("./module.wasm");
const { instance } = await WebAssembly.instantiate(buffer);
const memory = new Uint8Array(instance.exports.memory.buffer);

const rl = createInterface({ input, output });
const flag = (await rl.question("Enter the flag: ")).trim();
rl.close();

for (let i = 0; i < flag.length; i++) {
    memory[i] = flag.charCodeAt(i);
}

if (flag.length === 43 && instance.exports.check()) {
    console.log("nice job!");
} else {
    console.log("nope.");
}
```

So the flag is a 43‑byte string placed at memory offsets `0..42`, and `check()` returns `1` if and only if the flag is correct.

Goal: recover the 43 bytes that make `check()` return `1`.

---

## Step 1 – Decompiling the WebAssembly

First, decompile the WASM to something readable. Using WABT:

```bash
wasm2wat module.wasm -o module.wat
wasm-decompile module.wasm -o module.decompiled.c
```

`module.wat` is the textual WAT form; `module.decompiled.c` is a C-like decompilation of the only function `check`.

The decompiled code (slightly formatted) looks like:

```c
export memory memory(initial: 1, max: 0);

export function check():int { // func0
  if ((6[0]:ubyte + 38[0]:ubyte - 31[0]:ubyte -
       ((3[0]:ubyte &
         (21[0]:ubyte ^ 41[0]:ubyte) -
         (12[0]:ubyte | 13[0]:ubyte) * 26[0]:ubyte) |
        (2[0]:ubyte | 35[0]:ubyte + 39[0]:ubyte)) |
       20[0]:ubyte - 4[0]:ubyte - 30[0]:ubyte) !=
      110) {
    return 0;
  }
  if ((10[0]:ubyte | 36[0]:ubyte) != 95) { return 0; }
  if (((27[0]:ubyte ^ 8[0]:ubyte) & 15[0]:ubyte) != 45) { return 0; }
  if (((33[0]:ubyte ^
        (1[0]:ubyte * (42[0]:ubyte * 37[0]:ubyte ^ 24[0]:ubyte * 18[0]:ubyte) ^
         25[0]:ubyte)) &
       19[0]:ubyte) !=
      100) {
    return 0;
  }
  if ((0[0]:ubyte ^ 28[0]:ubyte) != 23) { return 0; }
  if ((34[0]:ubyte & 16[0]:ubyte) != 82) { return 0; }
  if ((22[0]:ubyte & 29[0]:ubyte) != 48) { return 0; }
  if ((5[0]:ubyte | 14[0]:ubyte) != 119) { return 0; }
  if ((7[0]:ubyte & 17[0]:ubyte) != 97) { return 0; }
  if (40[0]:ubyte - 9[0]:ubyte != 24) { return 0; }
  if (11[0]:ubyte * 32[0]:ubyte - 23[0]:ubyte != 11569) { return 0; }
  if ((26[0]:ubyte & (21[0]:ubyte ^ 6[0]:ubyte)) != 0) { return 0; }
  if (((39[0]:ubyte & 20[0]:ubyte) ^ 10[0]:ubyte) != 86) { return 0; }
  if ((35[0]:ubyte &
       (40[0]:ubyte | (19[0]:ubyte - 9[0]:ubyte & 27[0]:ubyte) * 38[0]:ubyte)) !=
      32) {
    return 0;
  }
  if ((1[0]:ubyte & 41[0]:ubyte) != 33) { return 0; }
  if ((24[0]:ubyte + 34[0]:ubyte * 22[0]:ubyte * 14[0]:ubyte -
       (29[0]:ubyte ^ 23[0]:ubyte) &
       13[0]:ubyte) !=
      16) {
    return 0;
  }
  if ((5[0]:ubyte ^
       17[0]:ubyte -
       30[0]:ubyte + (33[0]:ubyte + 18[0]:ubyte + 36[0]:ubyte ^ 25[0]:ubyte)) !=
      -504) {
    return 0;
  }
  if ((32[0]:ubyte & 42[0]:ubyte) * 4[0]:ubyte - 3[0]:ubyte - 8[0]:ubyte !=
      9344) {
    return 0;
  }
  ...
  if (19[0]:ubyte +
      (11[0]:ubyte ^ ((4[0]:ubyte * 5[0]:ubyte & 8[0]:ubyte) ^ 30[0]:ubyte)) !=
      108) {
    return 0;
  }
  return 1;
}
```

There are 60 separate `if (...) return 0;` checks, all involving indices from `0` to `42`. Each index `i` corresponds to the byte `flag[i]`.

Key observation: for the flag to be accepted, **every one** of those `if` conditions must be false. Since they are all of the form:

```c
if (EXPR != CONST) { return 0; }
```

success requires `EXPR == CONST` for every such line.

You *could* try to solve these equations by hand, but they’re intentionally messy: mixed arithmetic, bitwise AND/OR/XOR, and some large constants.

This is a perfect job for an SMT solver.

---

## Step 2 – Modelling the Check with Z3 (direct decompiled approach – unsat)

My first approach was to take the decompiled C-like conditions directly and turn them into Z3 constraints:

1. Create 43 8‑bit bit-vectors `b0..b42`.
2. Zero-extend them to 32 bits as `BZ[i]` so we can safely do arithmetic in 32-bit.
3. Regex-replace occurrences of `n[0]:ubyte` with `BZ[n]`.
4. `eval` each `if` condition into a Z3 expression, then require it to be false (`Not(cond)`).

Pseudo-code:

```python
from z3 import *
import re

text = open('module.decompiled.c').read()
conds = re.findall(r'if\\s*\\((.*?)\\)\\s*\\{\\s*return 0', text, flags=re.S)

B  = [BitVec(f"b{i}", 8) for i in range(43)]
BZ = [ZeroExt(24, b) for b in B]

s = Solver()
for raw in conds:
    expr = " ".join(line.strip() for line in raw.splitlines())
    expr = re.sub(r"(\\d+)\\[0\\]:ubyte", r"BZ[\\1]", expr)
    cond = eval(expr, {"BZ": BZ, "__builtins__": {}}, {})
    s.add(Not(cond))

print(s.check())
```

However, this gave `unsat`. That means my interpretation of the decompiler’s precedence/parentheses wasn’t fully faithful to the original WASM. The decompiled C code, while readable, had subtle differences in grouping compared to the actual stack-based instruction order.

So instead of trusting the decompiler, I switched to interpreting the **raw WAT** (`module.wat`) directly.

---

## Step 3 – Symbolic Execution of the WAT

In `module.wat`, `check` is expressed as straight-line stack operations using `i32.const`, `i32.load8_u`, `i32.add`, `i32.sub`, `i32.mul`, `i32.and`, `i32.or`, `i32.xor`, and `i32.ne`, with `if ... end` blocks for each check.

Example from `module.wat`:

```wat
    i32.const 10
    i32.load8_u
    i32.const 36
    i32.load8_u
    i32.or
    i32.const 95
    i32.ne
    if  ;; label = @1
      i32.const 0
      return
    end
```

Semantically, that’s:

```c
if ((flag[10] | flag[36]) != 95) return 0;
```

The idea:

1. Parse the instructions of the only function in `module.wat`.
2. Simulate the stack machine **symbolically** with Z3 bit-vectors instead of concrete integers.
3. Each time we hit `i32.ne` and then `if`, treat the top of the stack as the boolean condition `EXPR != CONST`.
4. Record that condition `cond`, and add `Not(cond)` to the solver.

### Symbolic interpreter

I wrote a small interpreter in Python that:

- Walks through `module.wat` to collect the instruction list for `func 0`.
- Keeps a stack of Z3 expressions.
- Handles: `i32.const`, `i32.load8_u`, `i32.add`, `i32.sub`, `i32.mul`, `i32.and`, `i32.or`, `i32.xor`, `i32.ne`, `if`, `end`, `return`.
- For `i32.load8_u`, it expects a constant address (which it always is here), and uses the corresponding `BZ[idx]` byte.
- For each `if`, it pops the condition and stores it; then skips over the `if { ... } end` block (which always just returns 0 on failure).

The core of the script looks like this:

```python
from z3 import *

lines = open('module.wat').read().splitlines()

in_func = False
instrs = []

for ln in lines:
    s = ln.strip()
    if not in_func:
        if s.startswith('(func '):
            in_func = True
        continue
    if s.startswith('(memory') or s.startswith('(export'):
        break
    if not s or s.startswith('('):
        continue
    if ';;' in s:
        s = s.split(';;', 1)[0].rstrip()
    s = s.rstrip(') ').strip()
    if not s:
        continue
    instrs.append(s)

# 8-bit flag bytes, zero-extended to 32-bit for arithmetic.
B  = [BitVec(f"b{i}", 8) for i in range(64)]
BZ = [ZeroExt(24, b) for b in B]

stack = []
conds = []

i = 0
while i < len(instrs):
    op = instrs[i]

    if op.startswith('i32.const'):
        _, val = op.split()
        stack.append(BitVecVal(int(val), 32))

    elif op == 'i32.load8_u':
        addr = stack.pop()
        idx = addr.as_long()  # always constant in this code
        stack.append(BZ[idx])

    elif op == 'i32.add':
        b, a = stack.pop(), stack.pop()
        stack.append(a + b)
    elif op == 'i32.sub':
        b, a = stack.pop(), stack.pop()
        stack.append(a - b)
    elif op == 'i32.mul':
        b, a = stack.pop(), stack.pop()
        stack.append(a * b)
    elif op == 'i32.and':
        b, a = stack.pop(), stack.pop()
        stack.append(a & b)
    elif op == 'i32.or':
        b, a = stack.pop(), stack.pop()
        stack.append(a | b)
    elif op == 'i32.xor':
        b, a = stack.pop(), stack.pop()
        stack.append(a ^ b)

    elif op == 'i32.ne':
        b, a = stack.pop(), stack.pop()
        stack.append(a != b)

    elif op.startswith('if'):
        cond = stack.pop()
        conds.append(cond)
        # Skip the body until matching 'end'
        depth = 1
        i += 1
        while i < len(instrs) and depth > 0:
            o2 = instrs[i]
            if o2.startswith('if'):
                depth += 1
            elif o2 == 'end':
                depth -= 1
            i += 1
        continue

    elif op in ('return', 'end'):
        pass
    else:
        raise RuntimeError(f"Unknown op: {op}")

    i += 1
```

After this, `conds` holds all 60 boolean expressions `EXPR != CONST` exactly as computed by the original WASM.

---

## Step 4 – Solving the Constraints

Now we wrap the collected conditions in a solver:

```python
s = Solver()

# restrict to printable ASCII to get a nice flag
for i in range(43):
    s.add(B[i] >= 32, B[i] <= 126)

for c in conds:
    # each 'if (EXPR != CONST) return 0;' means EXPR must equal CONST
    s.add(Not(c))

print("Solving...")
res = s.check()
print("result:", res)

if res == sat:
    m = s.model()
    vals = [m[B[i]].as_long() for i in range(43)]
    print("bytes:", vals)
    print("ascii:", "".join(chr(v) for v in vals))
```

Running this gives:

```text
result sat
bytes [97, 109, 97, 116, 101, 117, 114, 115, 67, 84, 70, 123, 119, 52, 115,
       109, 95, 97, 110, 100, 95, 115, 52, 116, 95, 115, 48, 108, 118, 51,
       114, 53, 95, 52, 114, 51, 95, 99, 48, 48, 108, 33, 125]
ascii amateursCTF{w4sm_and_s4t_s0lv3r5_4r3_c00l!}
```

Those bytes decode cleanly to:

```text
amateursCTF{w4sm_and_s4t_s0lv3r5_4r3_c00l!}
```

which also matches the expected CTF flag format.

---

## Step 5 – (Optional) Verification

If you have Node.js installed, you can plug this flag back into `main.mjs`:

```bash
echo 'amateursCTF{w4sm_and_s4t_s0lv3r5_4r3_c00l!}' | node main.mjs
```

and you should see:

```text
Enter the flag: nice job!
```

Alternatively, you could build a small host in any language that:

1. Instantiates `module.wasm`.
2. Writes the 43 bytes into memory.
3. Calls the exported `check()` function and confirms it returns `1`.

Given that our symbolic execution interpreted the **exact** WAT instruction sequence, and Z3 found a satisfying model, the solution is consistent with all 60 constraints.

---

## Final Flag

```text
amateursCTF{w4sm_and_s4t_s0lv3r5_4r3_c00l!}
```

