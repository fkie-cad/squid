// /riscv/bin/riscv64-unknown-linux-gnu-gcc -o test -fPIE -pie -O0 -g -fno-jump-tables -mno-relax -D__thread= test.c

#include <stdio.h>
#include <stdlib.h>

int main (int argc, char** argv) {
    if (argc < 2) {
        printf("USAGE: %s <index>\n", argv[0]);
        return 1;
    }

    int* array = malloc(16 * sizeof(int));
    int index = atoi(argv[1]);

    // Partially initialize array
    array[0] = 123;
    array[1] = 456;
    array[2] = 789;

    printf("array[%d] = %d\n", index, array[index]);
    
    return 0;
}

