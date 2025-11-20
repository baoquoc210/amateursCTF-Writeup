AmateursCTF – **functioning** (Reverse) Writeup
==============================================

## Challenge overview

> “i hope you like functions  
>  
> Note: correct input to the program should be the flag”

The challenge gives a single JavaScript file `chal.js`. It contains a huge nest of tiny functions (`a`–`h`, `A`–`K`) and a note that you may need to increase Node’s stack size, which is a hint that the program uses deep recursion.

At the very end of `chal.js` there is the actual check:

```js
if (!B(h(process.argv), b(b(d(a(), a()), d(a(), a())), c(d(a(), a()), d(a(), a())))) && K(process.argv[2])) {
    console.log("yes!");
}
```

So the script expects to be run like:

```bash
node chal.js <FLAG>
```

and prints `yes!` when the flag is correct.

The goal is to understand what `K(x)` (and inside it `J(x)`) does and recover the required flag.

---

## Step 1 – Understanding the basic building blocks

The file starts with a bunch of small helpers:

```js
const a = () => 0;
const b = (x, y) => x + y;
const c = (x, y) => x * y;
const d = (x, y) => x ** y;
const e = (x, y) => x & y;
const f = (x, y, z) => x ? y() : z();
const g = (x, y) => x.charCodeAt(y);
const h = (x) => x.length;
```

So:

- `a()` is just `0`.
- `b`, `c`, `d`, `e` are addition, multiplication, exponentiation and bitwise AND.
- `f(cond, then, else_)` is a functional ternary: `cond ? then() : else_()`.
- `g(x, i)` returns `x[i]` as a char-code.
- `h(x)` is the length of a string.

Everything else (`A`–`K`) is built from these, plus lots of composition and recursion. The idea of the challenge is basically “poor man’s lambda calculus”: arithmetic, comparisons, division, etc. are encoded via higher‑order functions instead of normal operators.

To safely experiment, I evaluated `chal.js` inside Python using the `quickjs` engine, stripping off the final `if` block so `process` wouldn’t be needed.

---

## Step 2 – Recovering the hidden arithmetic (A, B, C, …)

Instead of manually deobfuscating the giant expressions, it’s easier to treat them as black boxes and probe them with known inputs.

Using `quickjs` from Python, I evaluated each function for many random inputs and looked for patterns.

### A(x, y)

I printed a small table for `x, y ∈ [0, 16]`:

```
0 : [0, 255, 254, 253, ...]
1 : [1, 0, 255, 254, ...]
2 : [2, 1, 0, 255, ...]
...
16: [16, 15, 14, ..., 0]
```

From this pattern and random tests up to large values, it matches:

> **A(x, y) = (x − y) mod 256**

### B(x, y)

With a similar approach:

```js
const2 = b(b(d(a(), a()), d(a(), a())), c(d(a(), a()), d(a(), a())));
// const2 evaluated to 3
```

Testing `B(n, 3)` for `n = 0..9` gave:

``+
0 → 65533
1 → 65534
2 → 65535
3 → 0
4 → 1
...
```

This is exactly subtraction modulo 2¹⁶:

> **B(x, y) = (x − y) mod 2¹⁶**

### C(x, y)

Sampling `C(x, y)` for small values gave a staircase pattern:

```
0 : [1, 0, 0, 0, ...]
1 : [1, 1, 0, 0, ...]
2 : [1, 1, 1, 0, ...]
...
```

And randomized tests confirmed:

> **C(x, y) = 1 if x ≥ y else 0**

### D(x, y), E(x), F(x, y), G(x, y, z), H(x, y), I(x, y)

Similarly, by probing and matching against simple formulas:

- `E(x)` behaves like integer division by 256:

  ```text
  E(0..255)   = 0
  E(256..511) = 1
  E(512..767) = 2
  ...
  ```

  > **E(x) = ⌊x / 256⌋**

- `D(x, y)` matches:

  > **D(x, y) = (y − ⌊x / 256⌋) mod 2¹⁶**

  (verified extensively with random tests).

- `F(x, y)` again behaves exactly like `C(x, y)`:

  > **F(x, y) = 1 if x ≥ y else 0**

- `G` and `H` together act like division:

  - `H(x, y)` matches `⌊x / y⌋` for tested ranges.
  - `G(x, y, z)` matches `⌊x / y⌋ + z`.

- `I(x, y)` matches the remainder:

  > **I(x, y) = x mod y**

So all of these messy expressions are just re‑implementations of “normal” integer arithmetic and comparisons, using the tiny primitives.

---

## Step 3 – What does K(x) enforce?

`K` is defined near the end as:

```js
const K = (x) => f(
  A(h(x), <huge-constant>),
  a,
  () => J(x)
);
```

Evaluating the `<huge-constant>` expression gives `48`. Using the deobfuscated meaning of `A`, that condition is:

```js
A(h(x), 48) === (h(x) - 48) & 0xFF
```

- If `h(x) == 48`, then `A(h(x), 48) == 0` (falsy).
- Otherwise it’s a non‑zero number (truthy).

Remember `f(cond, then, else_)` is `cond ? then() : else_()`. So:

- If `h(x) != 48`, `K(x)` returns `a()`, which is `0` (falsy).
- If `h(x) == 48`, `K(x)` returns `J(x)`.

In other words:

> **K(x) enforces that the input length is exactly 48, and then delegates to `J(x)` for the real flag check.**

The other part of the final `if`:

```js
!B(h(process.argv), 3)
```

uses `B(x, y) = (x - y) mod 2¹⁶`. For `B(h(process.argv), 3)` to be `0`, we need `h(process.argv) == 3`. In Node, `process.argv` is `[node, script, user_input]`, so the script is just checking it was called with exactly one argument (the candidate flag).

So the effective condition is:

> “Node was called with exactly one argument **and** `J(flag)` is non‑zero, where `flag` has length 48”.

---

## Step 4 – Isolating and simplifying J(x)

`J(x)` is enormously long: a giant nest of `f(...)` calls involving `B`, `I`, `H`, and many `g(x, index)` calls. The important observations:

- It never mutates anything; it’s pure arithmetic on `g(x, i)` character codes and constants.
- The recursion is implemented via the `f` combinator. Essentially, you have a chain:

  ```js
  f(cond0, () => f(cond1, () => f(cond2, ... ), () => ...), () => ...)
  ```

  Each `condN` is a big expression. If `condN` is non‑zero, `f` short‑circuits and returns something; if it’s zero, it proceeds to the next `f`.

Using the earlier deobf results, I built a new file `deobf.js` that:

- Redefines `A`–`I` using the simple formulas instead of the massive expressions.
- Copies the original `J(x)` definition unchanged.

This keeps the exact same logic for `J`, just with arithmetic made explicit and much faster to reason about.

---

## Step 5 – Seeing which characters matter

To understand the structure of `J`, I instrumented the `g` function in `deobf.js`:

```js
let log = [];
const g = (x, y) => { log.push(y); return x.charCodeAt(y); };
```

Running `J` on a dummy 48‑character string and then inspecting `log` showed:

- Only indices `0` through `47` are ever used.
- Initially, `J` touched indices `[44, 45, 46, 47]`.

To go deeper, I parsed `deobf.js` with `esprima` (a JS parser for Python), located the `J` definition, and walked the AST to extract each nested `cond` used in the chain of `f` calls. There are **24** such conditions.

For each condition, I wrapped it in a small JS function `cond_i(x)` and re‑instrumented `g` to see which positions it uses. This produced:

```text
Cond 0:  positions [44, 45, 46, 47]
Cond 1:  positions [42, 43, 44, 45]
Cond 2:  positions [40, 41, 42, 43]
...
Cond 21: positions [2, 3, 4, 5]
Cond 22: positions [0, 1, 2, 3]
Cond 23: positions [0, 1, 46, 47]
```

So `J` imposes a chain of constraints on overlapping 4‑character windows of the 48‑character flag, with the last condition tying the start and end together.

---

## Step 6 – Turning J(x) into equations (Z3)

At this point, `J(x)` is:

- A pure function of the 48 characters of `x`.
- Implemented entirely via our known primitives:
  - `a, b, c, d, e, g, h, A, B, D, E, G, H, I`.
- Structured as nested `f(cond, ..., ...)` calls, ending in `d(a(), a()) = 0**0 = 1` (truthy).

The crucial semantic detail is how these `f` calls are chained:

- Each `f(cond, then, else_)` first evaluates `cond`.
- If **any** `cond` in the chain is non‑zero, `J(x)` will short‑circuit and end up as `0`.
- For `J(x)` to return the final `1`, **every** `cond` must evaluate to `0`.

So the flag is precisely the string for which **all 24 conditions evaluate to 0**.

To solve this, I:

1. Parsed `deobf.js` with `esprima` and extracted the AST for each condition `cond_i`.
2. Wrote a small AST interpreter for these expressions in Python, using our deobfuscated semantics:

   - `g(x, idx)` → the character at position `idx`.
   - `A`, `B`, `D`, `E`, `G`, `H`, `I` implemented as the simple formulas above.

3. Wrote a second interpreter that converts the AST into Z3 bit‑vector expressions over unknown bytes:

   ```python
   from z3 import BitVec, BitVecVal, ZeroExt, UDiv, URem, Solver

   # 48 unknown 8‑bit characters
   chars = [BitVec(f'c{i}', 8) for i in range(48)]

   # Each g(x, idx) becomes ZeroExt(chars[idx]) to a 16‑bit value.
   # A, B, D, E, G, H, I become arithmetic on 16‑bit bit‑vectors.
   ```

4. For each character, I constrained it to be printable ASCII:

   ```python
   32 <= c_i <= 126
   ```

5. For each condition `cond_i`, I added:

   ```python
   cond_i(chars) == 0
   ```

6. Asked Z3 to solve the system.

Z3 quickly responded with `sat` and produced a unique solution for the 48 characters:

```text
amateursCTF{po0r_m4ns_lambd4_c4lculus_45b538a09}
```

This already satisfies the length requirement (`48` characters).

---

## Step 7 – Verifying the flag

As a sanity check, using the simplified environment (`deobf.js`), I ran:

```js
J("amateursCTF{po0r_m4ns_lambd4_c4lculus_45b538a09}");
```

and confirmed:

- `J(flag) == 1` (truthy), while random strings almost always give `0`.
- The length is exactly `48`, so `K(flag)` returns `J(flag)`, which is non‑zero.

Putting everything together, when run as:

```bash
node chal.js amateursCTF{po0r_m4ns_lambd4_c4lculus_45b538a09}
```

the condition

```js
!B(h(process.argv), 3) && K(process.argv[2])
```

is satisfied, and the program prints `yes!`.

---

## Final flag

The recovered flag is:

```text
amateursCTF{po0r_m4ns_lambd4_c4lculus_45b538a09}
```

Conceptually, the challenge hides a straightforward series of arithmetic constraints and sliding‑window checks over the input string, but wraps them in a dense forest of higher‑order functions to look like inscrutable lambda calculus. By experimentally recovering the arithmetic primitives and then feeding the resulting equations into a solver, we can mechanically recover the only string that passes all of `J`’s checks.

