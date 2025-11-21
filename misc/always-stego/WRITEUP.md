# always-stego – Writeup (Misc, 361 pts, 13 solves)

## Challenge Info

- **Category:** Misc
- **Name:** always-stego
- **Points:** 361
- **Solves:** 13
- **Description:**
  > why is it always stego? it's so frequently stego that even i just hate it all-redy...
  >
  > **Hint:** It is not any type of standard stego, but the flavortext hints apply. Random jpeg compression artifacts are just noise and shouldn't be visually interpreted.

We’re given a single image: `output.png`.

## Intuition from the Flavortext

Key hints hidden in the text:

- **"always stego"** → there is an image; we expect some kind of hiding.
- **"so frequently stego"** → suggests **frequency analysis** rather than pixel-by-pixel tricks.
- **"all-redy"** → pun on *already* / *all red* → focus on the **red channel**.
- **"Random jpeg compression artifacts are just noise and shouldn't be visually interpreted."**  
  → don’t stare at the image or try visual tricks; the data is in numerical/statistical properties.

This strongly suggests:

- Use **histograms / frequencies** of the **red channel values**, not standard LSB or visual stego.

## Core Idea

Instead of reading raw pixel bits, we treat the image as a **container for a histogram-based code**:

1. Take the **red channel** of all pixels.
2. Compute the **frequency (histogram)** of each red value (0–255).
3. Use the frequencies themselves as the data channel:
   - Specifically, look only at **even** red values (0, 2, 4, …, 254).
   - For each such bin, take **count mod 256** → one byte.
4. Concatenate these bytes and search for the flag string.

So the “stego” is encoded in the **frequency distribution** of red values, not in the visible image content.

## Exploit Script

Using `Pillow` and `numpy`:

```python
from PIL import Image
import numpy as np
import re

img = np.array(Image.open("output.png"))
histR = np.bincount(img[:, :, 0].ravel(), minlength=256)

# even bins of red, mod 256
data = bytes([count % 256 for count in histR[::2]])

flag = re.search(rb"amateursCTF\{.*?\}", data).group(0).decode()
print(flag)
```

Explanation:

- `img[:, :, 0]` – red channel of the image.
- `np.bincount(..., minlength=256)` – histogram: count of each red value 0–255.
- `histR[::2]` – only **even** red values.
- `count % 256` – each count becomes a byte.
- Regex extracts the standard flag format `amateursCTF{...}` from the decoded byte stream.

## Flag

Running the script on `output.png` gives:

```text
amateursCTF{fr3quency_analys1s_ftw_7975491d}
```

**Flag:** `amateursCTF{fr3quency_analys1s_ftw_7975491d}`

