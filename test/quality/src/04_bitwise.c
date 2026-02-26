/* Test 4: Bitwise operations and masks */
#include <stdint.h>

uint32_t set_bit(uint32_t val, int bit) {
    return val | (1u << bit);
}

uint32_t clear_bit(uint32_t val, int bit) {
    return val & ~(1u << bit);
}

int count_ones(uint32_t x) {
    int count = 0;
    while (x) {
        count += x & 1;
        x >>= 1;
    }
    return count;
}

uint32_t rotate_left(uint32_t val, int n) {
    n &= 31;
    return (val << n) | (val >> (32 - n));
}

uint32_t extract_bits(uint32_t val, int start, int len) {
    uint32_t mask = (1u << len) - 1;
    return (val >> start) & mask;
}

int is_power_of_two(uint32_t x) {
    return x != 0 && (x & (x - 1)) == 0;
}

uint32_t next_power_of_two(uint32_t x) {
    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    return x + 1;
}

uint16_t byte_swap16(uint16_t val) {
    return (val >> 8) | (val << 8);
}

uint32_t byte_swap32(uint32_t val) {
    return ((val >> 24) & 0xFF) |
           ((val >> 8)  & 0xFF00) |
           ((val << 8)  & 0xFF0000) |
           ((val << 24) & 0xFF000000);
}
