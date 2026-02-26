/* Test 19: Complex expressions, operator precedence, compound assignments */
#include <stdint.h>

int complex_condition(int a, int b, int c, int d) {
    if ((a > 0 && b > 0) || (c < 0 && d < 0)) {
        return 1;
    }
    if (a >= b && (c == d || a != 0)) {
        return 2;
    }
    return 0;
}

uint32_t bit_manipulation_chain(uint32_t x) {
    x = (x | (x >> 1)) & 0x55555555;
    x = (x | (x >> 2)) & 0x33333333;
    x = (x | (x >> 4)) & 0x0F0F0F0F;
    x = (x | (x >> 8)) & 0x00FF00FF;
    x = (x | (x >> 16)) & 0x0000FFFF;
    return x;
}

int compound_ops(int *arr, int n) {
    int sum = 0;
    int product = 1;
    for (int i = 0; i < n; i++) {
        sum += arr[i];
        product *= arr[i];
        arr[i] <<= 1;
        arr[i] |= 1;
        arr[i] &= 0xFF;
    }
    return sum ^ product;
}

long long shift_arithmetic(long long val, int shift, int is_signed) {
    if (is_signed) {
        return val >> shift;
    }
    return (unsigned long long)val >> shift;
}

int nested_ternary(int a, int b, int c) {
    return a > b ? (a > c ? a : c) : (b > c ? b : c);
}
