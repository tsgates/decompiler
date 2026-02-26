/* Test 12: Ternary/conditional move patterns */

int abs_val(int x) {
    return x < 0 ? -x : x;
}

int min2(int a, int b) {
    return a < b ? a : b;
}

int max2(int a, int b) {
    return a > b ? a : b;
}

int clamp(int val, int lo, int hi) {
    if (val < lo) return lo;
    if (val > hi) return hi;
    return val;
}

int sign(int x) {
    return (x > 0) - (x < 0);
}

unsigned int abs_diff(unsigned int a, unsigned int b) {
    return a > b ? a - b : b - a;
}

int conditional_inc(int *counter, int condition) {
    if (condition) {
        *counter += 1;
        return 1;
    }
    return 0;
}
