/* Test 15: Variable-length argument patterns and stack-heavy functions */
#include <string.h>

/* Simulate printf-like formatting without actual varargs */
int format_int(char *buf, int bufsize, int val) {
    char tmp[20];
    int len = 0;
    int neg = 0;

    if (val < 0) { neg = 1; val = -val; }
    if (val == 0) { tmp[len++] = '0'; }
    else {
        while (val > 0) {
            tmp[len++] = '0' + (val % 10);
            val /= 10;
        }
    }
    if (neg) tmp[len++] = '-';

    if (len >= bufsize) return -1;
    for (int i = 0; i < len; i++) {
        buf[i] = tmp[len - 1 - i];
    }
    buf[len] = '\0';
    return len;
}

int format_hex(char *buf, int bufsize, unsigned int val) {
    const char hex[] = "0123456789abcdef";
    char tmp[16];
    int len = 0;

    if (val == 0) { tmp[len++] = '0'; }
    else {
        while (val > 0) {
            tmp[len++] = hex[val & 0xF];
            val >>= 4;
        }
    }

    if (len + 2 >= bufsize) return -1;
    buf[0] = '0';
    buf[1] = 'x';
    for (int i = 0; i < len; i++) {
        buf[i + 2] = tmp[len - 1 - i];
    }
    buf[len + 2] = '\0';
    return len + 2;
}

void fill_buffer(char *buf, int n, char c) {
    memset(buf, c, n);
}
