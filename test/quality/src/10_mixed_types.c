/* Test 10: Mixed type operations, casts, and type promotions */
#include <stdint.h>
#include <float.h>

float int_to_float(int x) {
    return (float)x;
}

int float_to_int(float x) {
    return (int)x;
}

double average(int *arr, int n) {
    if (n <= 0) return 0.0;
    long long sum = 0;
    for (int i = 0; i < n; i++) {
        sum += arr[i];
    }
    return (double)sum / n;
}

uint64_t multiply_extend(uint32_t a, uint32_t b) {
    return (uint64_t)a * (uint64_t)b;
}

int32_t saturating_add(int32_t a, int32_t b) {
    int64_t result = (int64_t)a + (int64_t)b;
    if (result > INT32_MAX) return INT32_MAX;
    if (result < INT32_MIN) return INT32_MIN;
    return (int32_t)result;
}

uint8_t clamp_byte(int val) {
    if (val < 0) return 0;
    if (val > 255) return 255;
    return (uint8_t)val;
}

int sign_extend_16to32(int16_t val) {
    return (int32_t)val;
}

uint32_t zero_extend_16to32(uint16_t val) {
    return (uint32_t)val;
}

/* Packed struct access */
typedef struct __attribute__((packed)) {
    uint8_t  tag;
    uint32_t value;
    uint16_t flags;
} PackedRecord;

uint32_t read_packed_value(const PackedRecord *r) {
    return r->value;
}

uint16_t read_packed_flags(const PackedRecord *r) {
    return r->flags;
}
