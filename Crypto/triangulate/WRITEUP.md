## triangulate Crypto Challenge – Writeup

### Challenge Overview

We are given a single script:

```python
#!/usr/local/bin/python3

from random import getrandbits
from Crypto.Util.number import *

flag = bytes_to_long(open('flag.txt', 'rb').read())
k = flag.bit_length()
m = getPrime(flag.bit_length() + 1)


def lcg():
    seed = flag
    a = getrandbits(k)
    c = getrandbits(k)
    ctr = 0
    while True:
        ctr += 1
        for _ in range(ctr):
            seed = (a * seed + c) % m
        yield seed

rng = iter(lcg())

for _ in range(6):
    print(next(rng))
```

and six concrete outputs (shortened here):

```text
O1 = 1471207943545852...509747415
O2 = 1598692736073482...345381739153
O3 = 7263027854980708...9835570092536173
O4 = 1421793811298953...494676689549954
O5 = 7461500488401740...4358955488744365
O6 = 7993378969370214...3336003815658573
```

Goal: recover the hidden `flag.txt`. The flag format is `amateursCTF{...}`.

---

### 1. Understanding the strange LCG

In a standard LCG,

\[
S_{n+1} = (a S_n + c) \bmod m
\]

with fixed parameters `a, c, m` and one update per step.

This challenge instead does:

- `seed` is initialized from the flag: `S_0 = flag`.
- It chooses random `a, c` of `k` bits where `k = flag.bit_length()`.
- `m` is a prime of size `k + 1` bits.
- On iteration `ctr`, it applies the LCG update `ctr` times before yielding the state.

Write `O_i` for the printed outputs (`O_i = S_i`).

- Step 1 (`ctr = 1`):
  \[
  O_1 = S_1 = a S_0 + c \pmod m.
  \]
- Step 2 (`ctr = 2`), starting from `O_1`:
  \[
  S_2 = a(a O_1 + c) + c = a^2 O_1 + a c + c \pmod m,\quad O_2 = S_2.
  \]
- Step 3 (`ctr = 3`), starting from `O_2`:
  \[
  S_3 = a^3 O_2 + a^2 c + a c + c \pmod m,\quad O_3 = S_3.
  \]

In general, the relation between consecutive outputs is

\[
O_i \equiv a^i O_{i-1} + c \cdot \frac{a^i - 1}{a - 1} \pmod m.
\]

Introduce

\[
X = \frac{c}{a - 1} \pmod m.
\]

Then the recurrence simplifies to

\[
O_i + X \equiv a^i (O_{i-1} + X) \pmod m.
\]

So the “shifted” sequence `T_i = O_i + X` behaves like a multiplicative sequence where each step uses `a^i` as the multiplier.

We know `O_1, …, O_6`, but not `a`, `c`, `X`, `m`, or the initial seed `S_0 = flag`.

---

### 2. Eliminating `a` and deriving equations in `X`

From

- \((O_2 + X)/(O_1 + X) \equiv a^2\),
- \((O_3 + X)/(O_2 + X) \equiv a^3\),
- \((O_4 + X)/(O_3 + X) \equiv a^4\),
- \((O_5 + X)/(O_4 + X) \equiv a^5\),

we can eliminate the unknown base `a` using relations between powers like \(a^2 a^3 = a^5\) and \((a^2)^2 = a^4\).

#### 2.1 Linear relation for `X`

Using \(a^2 a^3 = a^5\):

\[
\frac{O_2+X}{O_1+X} \cdot \frac{O_3+X}{O_2+X}
\equiv
\frac{O_5+X}{O_4+X}
\Rightarrow
\frac{O_3+X}{O_1+X} \equiv \frac{O_5+X}{O_4+X} \pmod m.
\]

Cross‑multiplying:

\[
(O_3+X)(O_4+X) \equiv (O_5+X)(O_1+X) \pmod m.
\]

Expand both sides:

- LHS: \(X^2 + (O_3+O_4)X + O_3O_4\),
- RHS: \(X^2 + (O_5+O_1)X + O_5O_1\).

The \(X^2\) terms cancel, leaving a *linear* congruence in `X`:

\[
\big[(O_3+O_4) - (O_5+O_1)\big] X + (O_3O_4 - O_5O_1) \equiv 0 \pmod m.
\]

Define

- \(C_1 = (O_3 + O_4) - (O_5 + O_1)\),
- \(C_0 = (O_3 O_4) - (O_5 O_1)\).

Then

\[
C_1 X + C_0 \equiv 0 \pmod m \quad\Longrightarrow\quad X \equiv -C_0 \cdot C_1^{-1} \pmod m.
\]

We don’t know `m` yet, but algebraically this shows that

\[
X = -\frac{C_0}{C_1}
\]

as a rational number over the integers, and modulo the true `m` it reduces to the same value.

#### 2.2 Second relation to recover `m`

Next use \((a^2)^2 = a^4\):

\[
\left(\frac{O_2+X}{O_1+X}\right)^2 \equiv \frac{O_4+X}{O_3+X} \pmod m.
\]

Rearrange:

\[
(O_2+X)^2 (O_3+X) - (O_4+X)(O_1+X)^2 \equiv 0 \pmod m.
\]

This is a polynomial \(Q(X)\) with integer coefficients such that \(Q(X) \equiv 0 \pmod m\).

Let

- \(u = O_2\), \(v = O_3\),
- \(w = O_4\), \(z = O_1\).

Then

- \((X+u)^2(X+v) = X^3 + (2u+v)X^2 + (u^2+2uv)X + u^2v\),
- \((X+w)(X+z)^2 = X^3 + (w+2z)X^2 + (2zw+z^2)X + wz^2\).

Subtracting, we get

\[
Q(X) = A_{\text{quad}} X^2 + B_{\text{quad}} X + C_{\text{quad}},
\]

where

- \(A_{\text{quad}} = (2u + v) - (w + 2z)\),
- \(B_{\text{quad}} = (u^2 + 2uv) - (2zw + z^2)\),
- \(C_{\text{quad}} = (u^2 v) - (w z^2)\).

Now substitute \(X = -C_0 / C_1\). To stay in integers, multiply by \(C_1^2\):

\[
\text{Val} = A_{\text{quad}}(-C_0)^2 + B_{\text{quad}}(-C_0)C_1 + C_{\text{quad}}C_1^2.
\]

Since \(Q(X) \equiv 0 \pmod m\), we must have

\[
 \text{Val} \equiv 0 \pmod m \quad\Rightarrow\quad m \mid \text{Val}.
\]

So the true modulus `m` is a divisor of this big integer `Val`.

We can derive another similar relation from \(a^2 a^4 = a^6\) involving \((O_2,O_4,O_5)\) and \((O_6,O_1,O_3)\), compute the corresponding value `Val2`, and then take

\[
m_{\text{full}} = \gcd(\text{Val}, \text{Val2}),
\]

which isolates `m` up to small factors (like 2 or 3).

In the challenge instance this GCD gives

```text
m_full (odd) = 27087529860673607876609504238950902993177393750404409357321895549765486040574683380702624928186845413174077
```

Factoring reveals:

```text
m_full = 3 * 9029176620...1804391359   (a large 352‑bit prime)
```

So the actual modulus used by the LCG is the large prime

```text
m = 9029176620224535958869834746316967664392464583468136452440631849921828680191561126900874976062281804391359
```

(We just set `m = m_full // 3`.)

---

### 3. Recovering `X`, `a`, and finally the flag

Once `m` is known, we can work modulo `m`:

1. Solve the linear equation for `X`:

   ```python
   X = (-C0 * pow(C1, -1, m)) % m
   ```

2. From the recurrence

   \[
   O_2 + X \equiv a^2 (O_1 + X),\quad
   O_3 + X \equiv a^3 (O_2 + X),
   \]

   we can compute \(a\) directly via

   \[
   a = \frac{(O_3+X)(O_1+X)}{(O_2+X)^2} \pmod m,
   \]

   i.e. in code:

   ```python
   num = (O3 + X) * (O1 + X)
   den = pow(O2 + X, 2, m)
   a = (num * pow(den, -1, m)) % m
   ```

3. Recover the original seed `S_0 = flag`. From the very first step,

   \[
   O_1 + X \equiv a (S_0 + X) \pmod m \Rightarrow
   S_0 + X \equiv (O_1 + X)a^{-1} \pmod m,
   \]

   so

   \[
   S_0 \equiv (O_1 + X)a^{-1} - X \pmod m.
   \]

   Code:

   ```python
   inv_a = pow(a, -1, m)
   S0 = ((O1 + X) * inv_a - X) % m
   ```

4. Convert `S0` back to bytes and decode:

   ```python
   flag = long_to_bytes(S0)
   print(flag.decode())
   ```

This yields:

```text
amateursCTF{w0w_such_cr3ativ3_lcG_ch4ll3ngE}
```

---

### 4. Full solve script (`solve.py`)

The final standalone solver used:

```python
from Crypto.Util.number import long_to_bytes, GCD, isPrime

outputs = [
    1471207943545852478106618608447716459893047706734102352763789322304413594294954078951854930241394509747415,
    1598692736073482992170952603470306867921209728727115430390864029776876148087638761351349854291345381739153,
    7263027854980708582516705896838975362413360736887495919458129587084263748979742208194554859835570092536173,
    1421793811298953348672614691847135074360107904034360298926919347912881575026291936258693160494676689549954,
    7461500488401740536173753018264993398650307817555091262529778478859878439497126612121005384358955488744365,
    7993378969370214846258034508475124464164228761748258400865971489460388035990421363365750583336003815658573,
]

O1, O2, O3, O4, O5, O6 = outputs

# 1) Linear relation for X
C1 = (O3 + O4) - (O5 + O1)
C0 = (O3 * O4) - (O5 * O1)

# 2) Quadratic relation from (a^2)^2 = a^4
u, v = O2, O3
w, z = O4, O1

A_quad = (2 * u + v) - (w + 2 * z)
B_quad = (u * u + 2 * u * v) - (2 * z * w + z * z)
C_quad = (u * u * v) - (w * z * z)

Val = A_quad * ((-C0) ** 2) + B_quad * (-C0) * C1 + C_quad * (C1 ** 2)
candidate_m = abs(Val)

# 3) Second relation from a^2 * a^4 = a^6
u, v, w = O2, O4, O5
up, vp, wp = O6, O1, O3

A_rel2 = (u + v + w) - (up + vp + wp)
B_rel2 = (u * v + v * w + w * u) - (up * vp + vp * wp + wp * up)
C_rel2 = (u * v * w) - (up * vp * wp)

Val2 = A_rel2 * ((-C0) ** 2) + B_rel2 * (-C0) * C1 + C_rel2 * (C1 ** 2)

m_full = GCD(candidate_m, abs(Val2))

# Strip powers of 2 (modulus is odd)
while m_full % 2 == 0:
    m_full //= 2

print("m_full (odd):", m_full)

# Factor out small factor 3 to get the true prime modulus
assert m_full % 3 == 0
m = m_full // 3
print("m bitlen:", m.bit_length(), "isPrime(m)?", isPrime(m))

# 4) Recover X
X = (-C0 * pow(C1, -1, m)) % m

# 5) Recover a
num = (O3 + X) * (O1 + X)
den = pow(O2 + X, 2, m)
a = (num * pow(den, -1, m)) % m

# 6) Recover initial seed S0 = flag
inv_a = pow(a, -1, m)
S0 = ((O1 + X) * inv_a - X) % m

flag = long_to_bytes(S0)
print("Flag bytes:", flag)
print("Flag:", flag.decode())
```

Running it prints:

```text
Flag bytes: b'amateursCTF{w0w_such_cr3ativ3_lcG_ch4ll3ngE}'
Flag: amateursCTF{w0w_such_cr3ativ3_lcG_ch4ll3ngE}
```

---

### 5. Flag

```text
amateursCTF{w0w_such_cr3ativ3_lcG_ch4ll3ngE}
```

