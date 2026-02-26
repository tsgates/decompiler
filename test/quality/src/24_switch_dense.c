/* Test 24: Dense and sparse switch statements */

int opcode_dispatch(int opcode, int a, int b) {
    switch (opcode) {
        case 0: return a + b;
        case 1: return a - b;
        case 2: return a * b;
        case 3: return b != 0 ? a / b : 0;
        case 4: return a & b;
        case 5: return a | b;
        case 6: return a ^ b;
        case 7: return a << b;
        case 8: return a >> b;
        case 9: return ~a;
        case 10: return -a;
        case 11: return a > b ? a : b;
        case 12: return a < b ? a : b;
        default: return -1;
    }
}

int sparse_switch(int x) {
    switch (x) {
        case 1:    return 100;
        case 10:   return 200;
        case 100:  return 300;
        case 1000: return 400;
        case 9999: return 500;
        default:   return 0;
    }
}

const char* token_type_name(int type) {
    switch (type) {
        case 0: return "EOF";
        case 1: return "INT";
        case 2: return "FLOAT";
        case 3: return "STRING";
        case 4: return "IDENT";
        case 5: return "PLUS";
        case 6: return "MINUS";
        case 7: return "STAR";
        case 8: return "SLASH";
        case 9: return "LPAREN";
        case 10: return "RPAREN";
        case 11: return "LBRACE";
        case 12: return "RBRACE";
        case 13: return "SEMICOLON";
        case 14: return "COMMA";
        case 15: return "ASSIGN";
        default: return "UNKNOWN";
    }
}
