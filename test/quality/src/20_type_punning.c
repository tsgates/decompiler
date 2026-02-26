/* Test 20: Type punning, union tricks, and memory layout */
#include <stdint.h>
#include <string.h>

typedef union {
    float f;
    uint32_t u;
    int32_t i;
} FloatBits;

/* Fast inverse square root (Quake-like) */
float fast_inv_sqrt(float x) {
    FloatBits conv;
    conv.f = x;
    conv.u = 0x5f3759df - (conv.u >> 1);
    return conv.f;
}

int float_sign_bit(float x) {
    FloatBits fb;
    fb.f = x;
    return (fb.u >> 31) & 1;
}

float float_abs(float x) {
    FloatBits fb;
    fb.f = x;
    fb.u &= 0x7FFFFFFF;
    return fb.f;
}

/* Memory reinterpretation */
uint32_t read_le32(const uint8_t *buf) {
    return (uint32_t)buf[0] |
           ((uint32_t)buf[1] << 8) |
           ((uint32_t)buf[2] << 16) |
           ((uint32_t)buf[3] << 24);
}

void write_le32(uint8_t *buf, uint32_t val) {
    buf[0] = (uint8_t)(val);
    buf[1] = (uint8_t)(val >> 8);
    buf[2] = (uint8_t)(val >> 16);
    buf[3] = (uint8_t)(val >> 24);
}

/* Struct with different alignments */
typedef struct {
    uint8_t a;
    uint32_t b;
    uint8_t c;
    uint16_t d;
} MixedAlign;

int sum_mixed(const MixedAlign *m) {
    return m->a + m->b + m->c + m->d;
}
