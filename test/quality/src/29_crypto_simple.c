/* Test 29: Simple crypto-like operations (XOR, rotate, S-box) */
#include <stdint.h>

void xor_encrypt(uint8_t *data, int len, uint8_t key) {
    for (int i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

uint32_t rol32(uint32_t val, int n) {
    return (val << (n & 31)) | (val >> (32 - (n & 31)));
}

uint32_t ror32(uint32_t val, int n) {
    return (val >> (n & 31)) | (val << (32 - (n & 31)));
}

uint32_t simple_hash(const uint8_t *data, int len) {
    uint32_t h = 0;
    for (int i = 0; i < len; i++) {
        h ^= (uint32_t)data[i] << ((i & 3) * 8);
        h = rol32(h, 5);
        h += 0x9e3779b9;
    }
    return h;
}

void feistel_round(uint32_t *left, uint32_t *right, uint32_t key) {
    uint32_t temp = *right;
    *right = *left ^ (rol32(*right, 5) + key);
    *left = temp;
}

void feistel_encrypt(uint32_t *block, const uint32_t *keys, int rounds) {
    uint32_t left = block[0], right = block[1];
    for (int i = 0; i < rounds; i++) {
        feistel_round(&left, &right, keys[i]);
    }
    block[0] = left;
    block[1] = right;
}
