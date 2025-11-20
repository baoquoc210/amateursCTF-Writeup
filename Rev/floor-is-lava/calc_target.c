#include <stdio.h>
#include <stdlib.h>

int main(void) {
    for (int i = 0; i < 8; i++) {
        unsigned int seed = (unsigned int)(i * 0x1337u - 0x21524111u);
        srand(seed);
        int r = rand();
        unsigned char b = (unsigned char)r; // low 8 bits
        printf("row %d: seed=0x%08x rand=0x%08x byte=0x%02x\n", i, seed, r, b);
    }
    return 0;
}
