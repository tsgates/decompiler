/* Test 27: Bit fields and packed data */
#include <stdint.h>

typedef struct {
    uint32_t opcode : 6;
    uint32_t rd : 5;
    uint32_t funct3 : 3;
    uint32_t rs1 : 5;
    uint32_t rs2 : 5;
    uint32_t funct7 : 7;
    uint32_t unused : 1;
} RTypeInsn;

int decode_opcode(uint32_t insn) {
    return insn & 0x3F;
}

int decode_rd(uint32_t insn) {
    return (insn >> 6) & 0x1F;
}

int decode_rs1(uint32_t insn) {
    return (insn >> 14) & 0x1F;
}

int decode_rs2(uint32_t insn) {
    return (insn >> 19) & 0x1F;
}

uint32_t encode_r_type(int opcode, int rd, int funct3, int rs1, int rs2, int funct7) {
    return (opcode & 0x3F) |
           ((rd & 0x1F) << 6) |
           ((funct3 & 0x7) << 11) |
           ((rs1 & 0x1F) << 14) |
           ((rs2 & 0x1F) << 19) |
           ((funct7 & 0x7F) << 24);
}

int popcount(uint32_t x) {
    x = x - ((x >> 1) & 0x55555555);
    x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
    x = (x + (x >> 4)) & 0x0F0F0F0F;
    return (x * 0x01010101) >> 24;
}
