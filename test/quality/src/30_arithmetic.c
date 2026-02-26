/* Test 30: Arithmetic optimizations — div/mod tricks, strength reduction */
#include <stdint.h>

int divide_by_3(int x) { return x / 3; }
int divide_by_5(int x) { return x / 5; }
int divide_by_7(int x) { return x / 7; }
int divide_by_10(int x) { return x / 10; }

unsigned int udivide_by_3(unsigned int x) { return x / 3; }
unsigned int udivide_by_10(unsigned int x) { return x / 10; }

int modulo_3(int x) { return x % 3; }
int modulo_power_of_2(int x) { return x % 16; }
unsigned int umod_power_of_2(unsigned int x) { return x % 16; }

int multiply_by_15(int x) { return x * 15; }
int multiply_by_100(int x) { return x * 100; }

int is_aligned_16(int x) { return (x & 15) == 0; }
int align_up_16(int x) { return (x + 15) & ~15; }

int64_t multiply_64(int32_t a, int32_t b) {
    return (int64_t)a * (int64_t)b;
}
