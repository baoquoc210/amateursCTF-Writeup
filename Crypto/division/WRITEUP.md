## division Crypto Challenge – Writeup

### Challenge Overview

Given:

- `chall.sage` (encryption script)
- Hidden `flag.txt`

The Sage script:

```python
import random

flag = int.from_bytes(open('flag.txt', 'rb').read(), 'big')

x = flag.bit_length()
r = random.getrandbits(x*3)
s = random.getrandbits(x*3) >> x*2 << x*2
p = random_prime(2^(x*3)-1, False, 2^(x*3-1))
c = (r*flag+s)%p
print(f"{c = }")
print(f"{r = }") # just divide to get the flag
print(f"{p = }") # ok fine maybe you need the modulus as well
```

For the instance we’re given, the printed values are (shortened here):

- `c` – a 3405‑bit ciphertext
- `r` – a 3404‑bit random integer
- `p` – a 3405‑bit prime

Goal: recover the unknown `flag`.

---

### Understanding the Scheme

Let

- `m = flag`
- `x = m.bit_length()`

The script chooses:

- `r` uniformly in `[0, 2^(3x))`
- `s_raw` uniformly in `[0, 2^(3x))`, then
  ```python
  s = s_raw >> (2*x) << (2*x)
  ```
  so `s` is a multiple of `2^(2x)`:
  \[
    s = 2^{2x} \cdot k
  \]
  for some integer `k` with `0 ≤ k < 2^x`.
- `p` is a random prime of size ≈ `3x` bits.
- Ciphertext:
  \[
    c \equiv r m + s \pmod p
  \]

We know:

- `0 ≤ m < 2^x` (by definition of `x = flag.bit_length()`)
- `0 ≤ k < 2^x`
- `p` is about `2^(3x)`
- and there exists some integer `n` such that
  \[
    r m + 2^{2x} k - c = n p.
  \]

So we are looking for small integers `(m, k, n)` solving

\[
  r m + 2^{2x} k - c - n p = 0
\]

with the size bounds:

- `m`, `k`, `n` are all roughly at most `2^x`.

Just “dividing by `r`” doesn’t work because of the unknown additive term `s = 2^{2x} k`, but the special structure of `s` (it is a multiple of `2^(2x)` and is **small** compared to `p`) lets us build a lattice and use LLL to recover the small solution.

---

### Rewriting as a Short Vector Problem

Define:

- `S = 2^(2x)`

We want integers `(m, k, n)` with:

\[
  r m + S k - c = n p.
\]

Equivalently,

\[
  r m + S k - c - n p = 0.
\]

Consider the integer vector

\[
  v = (-n,\, m,\, k,\, 1).
\]

We will construct a 4‑dimensional lattice such that for the **true** solution `(m, k, n)` this vector (or a very close multiple/sign variant of it) is very short in that lattice. Then LLL on that lattice will return a reduced basis containing short vectors, from which we can recover `(m, k, n)` and therefore `m = flag`.

---

### Lattice Construction

Let `H` be a scaling factor (we will use `H = 2^(x+2)` in practice). Define the 4×4 integer matrix:

```text
[ p*H   0   0   0 ]
[ r*H   1   0   0 ]
[ S*H   0   1   0 ]
[ c*H   0   0   1 ]
```

Call this matrix `M`. Its rows generate a lattice `L ⊂ ℤ⁴`.

Take integer coefficients `(a0, a1, a2, a3)` and look at the integer combination:

\[
  a_0 \cdot (pH,0,0,0) +
  a_1 \cdot (rH,1,0,0) +
  a_2 \cdot (SH,0,1,0) +
  a_3 \cdot (cH,0,0,1).
\]

The first coordinate of this combination is

\[
  H (a_0 p + a_1 r + a_2 S + a_3 c).
\]

Now choose coefficients

\[
  (a_0, a_1, a_2, a_3) = (n,\,-m,\,-k,\,1).
\]

Then:

- First coordinate:
  \[
    H (n p - m r - k S + c) = 0,
  \]
  exactly because `r m + S k - c = n p`.
- The remaining coordinates are:
  \[
    (0,\,-m,\,-k,\,1).
  \]

So the true solution yields the lattice vector

\[
  v_{\text{true}} = (0,\,-m,\,-k,\,1),
  \quad \text{with } \|v_{\text{true}}\|^2 \approx m^2 + k^2 + 1.
\]

Since `m` and `k` are at most about `2^x`, this vector is *very short* compared to random lattice vectors whose coordinates involve numbers of size around `p`, `r`, `S`, `c` (≈ `2^(3x)` or `2^(2x)` when scaled).

The role of the scaling factor `H` is to ensure the first coordinate dominates the length whenever it is non‑zero; this discourages LLL from outputting vectors with a non‑zero (and thus huge) first coordinate. For the true solution, the first coordinate is exactly 0.

So, in summary:

- The real `(m, k, n)` gives a short lattice vector with first coordinate 0.
- All other “random” short vectors are much less likely to have first coordinate exactly 0 and at the same time small remaining coordinates bounded by `2^x`.

This is a standard kind of “hidden small solution” → “short vector in a carefully constructed lattice” reduction.

---

### Using LLL to Recover the Flag

We use the Python library `fpylll` to perform LLL reduction on `M` and then search for a short vector corresponding to the true `(m, k, n)`.

High‑level algorithm:

1. Parse the given `c`, `r`, `p` and compute `x = p.bit_length() // 3`.
2. Set `S = 1 << (2*x)` and `H = 1 << (x+2)`.
3. Build the integer matrix `M` as described above.
4. Run `LLL.reduction(M)` to obtain a reduced basis `M_red`.
5. Search for very short integer combinations of the reduced basis vectors:
   - Enumerate small coefficients (e.g. between −8 and 8),
   - Form the combination `v = Σ a_i · row_i` in ℤ⁴,
   - Keep only those with:
     - first coordinate exactly 0,
     - last coordinate small in absolute value,
     - second and third coordinates of size less than `2^x`.
   - For each candidate vector `v = (0, v1, v2, v3)`:
     - Let `m = v1`, `k = v2`.
     - Check whether there exists an integer `n` with
       \[
         r m + S k - c = n p.
       \]
       (i.e. `r*m + S*k - c` is divisible by `p`).
     - If yes and `m`, `k`, `n` are within the expected bounds, we accept `m` as the recovered flag.

This approach can be validated on many small‑`x` random instances; in testing, it reliably recovers the correct `m` up to at least `x = 40` bits, and works on the challenge parameters with `x = 1135`.

---

### Solving Script (Python)

Below is a condensed version of the script used to solve the provided instance.

Requirements:

- Python 3
- `sympy` (for big‑integer utilities, optional)
- `fpylll` and `cysignals`

```python
from itertools import product
from fpylll import IntegerMatrix, LLL

# --- paste the concrete values from chall.sage output here ---

c = 75375527234510651665677207066229891926040929328980582924525303994966835168796055022727363375804269692143070561263128516881074866977604549208239672350292604269324775848328528401041649243536698878068388663854658455888665567421528139676553398379791728850136444114360571254958597748469715514303229969364378553163423222522897412606507907342566717324675248648278152290809106176295241303943659155279739413927229119348178739649701446536277787785586385384290648596225479179951687047854987093302449400449408907035601103612171991422127378147919500898428845497702002243505620992542869790261271932282435731195032724808409252081154632950628964417018040860488194082532635686263681213906375790385569586239071410623996119802591938958940165788806391189899599255362316672332888493379847547083365240770226903398674774357924053797951490900058983308593594684075033516959188148000904700191560112121648591490057629599361214369099947477414730697724448515856824615139071844639957575363257387078768257241797937595586141467195592425033618924139126557481
r = 48648359606087607054764975061246586804946899771075465950463841480503792391242075718361379574064958310831886132797205905782225730921050328582127691139051377153885590959058584931544239373521818766047205266802911821810151109225243130179140623399478388305644784028218706385078397300157808478028917780169261334807047724247279925670091509482240375019889452543079342438321747327926834796379012339921188615926117511143813280492641218017371403897472661550045565397359426254471576804581357221127582353441561380497515665661934473669613838790969595463036823630557187360129867186459025552953339813671569683189170774295708055929734217591905795428441403136096735625270568765197391423757594103320945558276124412602379303298694436105059220213537852584622876964933389323070365214287371704961312345353833390325002117393017327937680001690416415146226901969211615033627210161600009415469801626322733646436539056402194785639655852044899338363041427982892348396424818762289291934998870311926616547712216114710383692009811315188831592384925859038824
p = 86177866064517609033880568807115953555242816860796465315994122793500658219204691266285400596992843986822859067988140541321102737268469256003488633194805732902328449668973675656034407479445206199285327332956250166678724833829086476894512753542599582930303813548509716626122990897384869145771777456521841989016732565902948058499497558560940675936638149144787557866682549895410172503475134761737103764159012832476099457080767621349093023525464199464437775892158425340808608831357847290625769994444619608418683397291585743320119410163556022541745013298562365924431890839096568358382609153300688137255847854540583022798338370905413030872305343628451395156651510799422269846199097346654778450970192181652155045761310415676411676415321314004703082183268372839586588063507099961869739615845147256459914569897668249853629651515566126984158856990492614415609777375564680454921886476795802100545467623117528820164062239760078312599781978838070617837964620704025708935814492400262083101517057997114593888320133983970592497555237407111597

x = p.bit_length() // 3
S = 1 << (2 * x)
H = 1 << (x + 2)

# Build the lattice basis
M = IntegerMatrix(4, 4)
M[0, 0] = p * H; M[0, 1] = 0;     M[0, 2] = 0; M[0, 3] = 0
M[1, 0] = r * H; M[1, 1] = 1;     M[1, 2] = 0; M[1, 3] = 0
M[2, 0] = S * H; M[2, 1] = 0;     M[2, 2] = 1; M[2, 3] = 0
M[3, 0] = c * H; M[3, 1] = 0;     M[3, 2] = 0; M[3, 3] = 1

M_red = LLL.reduction(M)

flag = None
K = 8  # search range for small integer combinations

for coeffs in product(range(-K, K + 1), repeat=4):
    if all(a == 0 for a in coeffs):
        continue
    v = [0, 0, 0, 0]
    for i, a in enumerate(coeffs):
        if a == 0:
            continue
        row = M_red[i]
        for j in range(4):
            v[j] += a * int(row[j])
    # We want vectors with first coord 0 and small last coord
    if v[0] != 0 or abs(v[3]) > K:
        continue
    m, k = v[1], v[2]
    lhs = r * m + S * k - c
    if lhs % p != 0:
        continue
    n = lhs // p
    # Check bounds (m, k, n roughly < 2^x)
    if not (0 <= m < (1 << x)):
        continue
    if not (0 <= k < (1 << x)):
        continue
    if not (0 <= n < (1 << x)):
        continue
    flag = m
    break

assert flag is not None

flag_bytes = flag.to_bytes((flag.bit_length() + 7) // 8, "big")
print(flag_bytes)
```

Running this script recovers:

```text
b'amateursCTF{the_flag_format_is_kinda_long_but_if_i_just_type_enough_text_here_it_doesnt_matter_righttttttttttttttttttttttttttt_yeahh_probably}'
```

---

### Final Flag

```text
amateursCTF{the_flag_format_is_kinda_long_but_if_i_just_type_enough_text_here_it_doesnt_matter_righttttttttttttttttttttttttttt_yeahh_probably}
```

