/* Test 22: Volatile and memory-mapped I/O patterns */
#include <stdint.h>

void mmio_write32(volatile uint32_t *addr, uint32_t val) {
    *addr = val;
}

uint32_t mmio_read32(volatile uint32_t *addr) {
    return *addr;
}

void mmio_set_bits(volatile uint32_t *addr, uint32_t mask) {
    *addr |= mask;
}

void mmio_clear_bits(volatile uint32_t *addr, uint32_t mask) {
    *addr &= ~mask;
}

int poll_status(volatile uint32_t *status_reg, uint32_t mask, int timeout) {
    for (int i = 0; i < timeout; i++) {
        if ((*status_reg & mask) != 0) return 0;
    }
    return -1;
}
