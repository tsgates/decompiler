/* Test 28: Large stack frames and many local variables */

int many_locals(int a, int b, int c, int d) {
    int x1 = a + b;
    int x2 = b + c;
    int x3 = c + d;
    int x4 = d + a;
    int y1 = x1 * x2;
    int y2 = x2 * x3;
    int y3 = x3 * x4;
    int y4 = x4 * x1;
    int z1 = y1 - y2;
    int z2 = y2 - y3;
    int z3 = y3 - y4;
    int z4 = y4 - y1;
    return z1 + z2 + z3 + z4;
}

void large_buffer(int *out, int n) {
    int buf[256];
    for (int i = 0; i < 256 && i < n; i++) {
        buf[i] = i * i;
    }
    for (int i = 0; i < 256 && i < n; i++) {
        out[i] = buf[255 - i];
    }
}

int many_params(int a, int b, int c, int d, int e, int f, int g, int h) {
    return a + b*2 + c*3 + d*4 + e*5 + f*6 + g*7 + h*8;
}

long long wide_multiply(int a, int b, int c, int d) {
    long long ab = (long long)a * b;
    long long cd = (long long)c * d;
    return ab + cd;
}
