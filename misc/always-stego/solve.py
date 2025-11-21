from PIL import Image
import numpy as np
import re


def main() -> None:
    img = np.array(Image.open("output.png"))
    hist_r = np.bincount(img[:, :, 0].ravel(), minlength=256)

    # even bins of red, mod 256
    data = bytes([count % 256 for count in hist_r[::2]])
    match = re.search(rb"amateursCTF\{.*?\}", data)
    if not match:
        raise ValueError("Flag pattern not found in decoded data")
    flag = match.group(0).decode()
    print(flag)


if __name__ == "__main__":
    main()

