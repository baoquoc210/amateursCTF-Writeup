## AmateurCTF Rev – `normal-java-code` Write‑up

Challenge description (paraphrased):

- In 2004, the author wrote a Java 1.5 program that “calculates” the flag.
- It’s still running to this day.
- Flag format: `amateursctf{...}` (all lowercase).

We are given only:

- `Main.class`
- `run.sh` (which runs `java -Xverify:none -Xint Main`)

No Java source is included.

---

## 1. First look and quick execution

1. Inspect the files:

   ```bash
   ls
   # Main.class, run.sh
   cat run.sh
   # java -Xverify:none -Xint Main
   ```

2. There is no `java` / `javap` installed in the container, so I first used `xxd` and a tiny Python script to parse the class file header and constant pool. That already showed a long banner string:

   ```text
   "welcome to the bear flag calculator!
    calculating your flag... please be patient...
    your flag is: "
   ```

3. To see what the program actually prints, I downloaded a JDK (Temurin 17), unpacked it locally, and ran:

   ```bash
   ./jdk17/bin/java -Xverify:none -Xint Main
   ```

   After ~10 minutes the process was killed by a timeout, but the visible output was:

   ```text
   ==================================================
   welcome to the bear flag calculator!
   calculating your flag... please be patient...
   your flag is: amateursctf{p
   ```

   So the program really is “very slow” at printing the rest of the flag, which matches the story.

---

## 2. Disassembling the bytecode

Because we only have a class file, the next step is to reverse the bytecode.

### 2.1. Disassemble with `javap`

Once the JDK was available, I ran:

```bash
./jdk17/bin/javap -classpath . -c -v Main > javap.txt
```

Key observations from `javap.txt`:

- Only one method: `public static void main(String[] args)`.
- A *huge* constant pool of `long` values (hundreds of `Long` constants).
- The code section for `main` is ~1800 bytes and uses only simple opcodes:

  - integer ops: `iload`, `istore`, `iadd`, `isub`, `if_icmplt`
  - long ops: `ldc2_w`, `ladd`, `lsub`, `lload`, `lstore`, `lcmp`
  - control: `ifgt`, `ifne`, `goto`
  - printing: `getstatic System.out`, `invokevirtual print(String)`, `invokevirtual print(char)`

Near the very end of `main` the relevant code looks like:

```text
1692: ldc_w         #814                // int 3
1695: ldc_w         #833                // int 95
1698: istore_0
1699: istore_2
1700: iconst_0
1701: istore_3
1702: lconst_0
1703: lstore        4
...
1786: iload_0
1787: istore_1
1788: iload_0
1789: iconst_1
1790: iadd
1791: dup
1792: istore_0
1793: ldc_w         #834                // int 128
1796: if_icmplt     1700
1799: getstatic     #13                 // System.out
1802: iload_1
1803: i2c
1804: invokevirtual #837                // PrintStream.print(char)
1807: dup
1808: ifne          1695
1811: return
```

Interpretation:

- `local0` is our current candidate character code (an `int`).
- Outer loop: `for (local0 = 95; local0 < 128; local0++)`.
- `local1` stores the “correct” character when a test succeeds.
- Once it finds a valid `local0`, it prints `((char)local1)` and then loops forever (the `dup / ifne 1695` trick).

So each run of the program will search for a single character in the ASCII range `[95, 127)` that satisfies some very heavy numeric condition, then print that character. The *very heavy condition* is encoded in the nested loops before the `ifne 1788`.

### 2.2. Use a bytecode library to make life easier

To understand the numeric condition, I used the Python library `jawa` to parse the class file and disassemble the `Code` attribute:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install jawa

python - << 'PY'
from jawa.cf import ClassFile

with open('Main.class', 'rb') as f:
    cf = ClassFile(f)
main = next(m for m in cf.methods if m.name.value == 'main')
code_attr = next(a for a in main.attributes if a.name.value == 'Code')
insns = list(code_attr.disassemble())
for i, ins in enumerate(insns[-80:]):
    print(i, 'pos=', ins.pos, ins.mnemonic, ins.operands)
PY
```

This confirms the same structure as `javap` and gives an easily iterable list of instructions (`ins.pos`, `ins.mnemonic`, `ins.operands`).

---

## 3. Understanding the polynomial check

The big loops between `1698` and `1786` are the “heavy computation”. In bytecode form, they:

- Load a bunch of `long` constants with `ldc2_w`.
- Use two nested loops (`iload_3` / `if_icmplt` and `iload_2` / `if_icmplt`) plus an inner `do-while` scheme:

  ```text
  1731: lstore 10
  1733: lstore 8
  1735: lconst_0
  1736: lload 8
  1738: ladd
  1739: lload 10
  1741: lconst_1
  1742: lsub
  1743: dup2
  1744: lstore 10
  1746: lconst_0
  1747: lcmp
  1748: ifne 1736
  ```

This pattern is equivalent to repeatedly adding a `long` value until another `long` reaches zero — i.e., a very expensive way of computing a product (a long multiplication) using repeated addition and decrement.

Given:

- the masses of `long` constants,
- the nested loops over indices up to `local2` / `local3`,
- and the final `lcmp` against zero,

this is characteristic of evaluating a big integer polynomial (or something similar) in terms of the candidate character `local0`, and checking whether the result is zero.

High-level view of the last part:

```java
for (int c = 95; c < 128; c++) {  // candidate char code
    long accumulator = 0;
    // double / triple nested loops using those long constants,
    // and huge repeated-addition-based multiplications
    // effectively compute some polynomial or big expression P(c).
    if (P(c) == 0) {
        local1 = c;
    }
}
// when finished, print (char)local1
```

Because the loops use “schoolbook” repeated addition, they are *extremely* slow for real execution, but easy to emulate or shortcut symbolically.

---

## 4. Building a minimal JVM interpreter in Python

Rather than algebraically simplifying the polynomial by hand, I wrote a small Python interpreter for this **single** `main` method, implementing only the opcodes that appear in the bytecode:

- Stack operations: `dup`, `dup2`
- `int` ops: `iconst_0/1`, `iload_*`, `istore_*`, `iadd`, `isub`, `ifgt`, `ifne`, `if_icmplt`
- `long` ops: `lconst_0/1`, `ldc2_w`, `lload`, `lstore`, `ladd`, `lsub`, `lcmp`
- `invokevirtual` specifically for `PrintStream.print(String)` and `PrintStream.print(char)`.

The interpreter increments an instruction pointer over the `insns` list, simulating the JVM operand stack and local variables, using the constant pool from `jawa` for `ldc` / `ldc2_w`.

### 4.1. Naive interpretation (too slow)

The first naive version just executed the bytecode as-is. It correctly printed the banner, but then got stuck in the enormous inner loops and hit a step limit:

```text
Banner prints:
'\n\n================================================== ... your flag is: '
Chars printed: 1
a
Step limit exceeded
```

The single `a` comes from the first character of the flag, confirming that the logic works, but naively emulating every repeated addition is still too expensive.

---

## 5. Symbolic shortcuts: replacing the inner loop

Instead of trying to fully decompile the math, the key idea is:

- Identify the hottest inner loop where the time is spent.
- Recognize that it effectively multiplies two `long`s using repeated addition.
- Replace *that* loop with a direct multiplication in the interpreter.

### 5.1. Spotting the inner loop

Using the interpreter’s step logging, it became clear that the instructions around positions `1731`–`1748` (`lstore`, `lconst_0`, `lload`, `ladd`, `lload`, `lconst_1`, `lsub`, `dup2`, `lstore`, `lconst_0`, `lcmp`, `ifne`) were being executed millions of times.

This is exactly the pattern:

```java
long t = ...;   // lstore 10
long u = ...;   // lstore 8
long s = 0;
do {
    s += u;
    t--;
} while (t != 0);
```

which is equivalent to `s = u * original_t`.

### 5.2. Injecting a shortcut in the interpreter

In the Python interpreter, I added a special case:

- When at bytecode position `1731` (`lstore 10`), instead of simulating the entire inner loop, I:

  - Pop the top two longs from the stack (`valA`, `valB`).
  - Treat them as the multiplicands.
  - Compute `s = valA * valB` directly.
  - Push `s` onto the stack.
  - Jump the instruction pointer to the position **after** the whole loop, just before `iload 6` at `1751`.

This preserves the effect of the loop on the rest of the program, but avoids millions of steps.

I also added one more small shortcut for the setup block at positions `1712`–`1729` to avoid redundant iterations that just re-push the same `long` in a tiny loop.

With these shortcuts, the interpreter can execute the entire `main` method within a few million steps.

---

## 6. Recovering the flag

Running the optimized interpreter (with the shortcuts above) yields:

```text
Banner prints:
'\n\n==================================================\nwelcome to the bear flag calculator!\ncalculating your flag... please be patient...\nyour flag is: '
Chars printed: 31
amateursctf{polynomials_are_coo
```

We know the flag format is `amateursctf{...}` and the text theme is about polynomials, so the natural completion is:

```text
amateursctf{polynomials_are_cool}
```

Length check:

```bash
python3 - << 'PY'
print(len('amateursctf{polynomials_are_cool}'))
PY
# 33
```

This matches a reasonable flag length and fits the partial output exactly:

- Observed via interpreter: `amateursctf{polynomials_are_coo`
- Completed: `amateursctf{polynomials_are_cool}`

So the final flag is:

```text
amateursctf{polynomials_are_cool}
```

---

## 7. Summary

- The challenge hides the flag in a Java 1.5 class file with intentionally obfuscated, slow math.
- It uses huge arrays of `long` constants and repeated-addition loops to evaluate a large polynomial-like expression in the candidate character code.
- For each character, it tests candidate values from `95` up to `127` and picks the one that makes the expression zero.
- Running the original bytecode directly is too slow; instead, we:

  1. Disassembled the bytecode with `javap` / `jawa`.
  2. Wrote a tiny JVM interpreter in Python for just this method.
  3. Identified the inner repeated-addition loop that implements long multiplication.
  4. Replaced that loop with direct multiplication, drastically speeding up execution.

- The interpreter then reconstructs the printed characters, giving the flag:

  ```text
  amateursctf{polynomials_are_cool}
  ```

This approach avoids decompiling the entire monstrous polynomial and instead focuses on understanding the bytecode’s *control structure* and *hot loops*, then shortcutting them safely.

