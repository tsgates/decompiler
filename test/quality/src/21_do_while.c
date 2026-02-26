/* Test 21: Do-while loops and unusual loop forms */
int count_trailing_zeros(unsigned int x) {
    if (x == 0) return 32;
    int n = 0;
    do { n++; x >>= 1; } while ((x & 1) == 0);
    return n;
}

int digits_sum(int n) {
    int sum = 0;
    if (n < 0) n = -n;
    do {
        sum += n % 10;
        n /= 10;
    } while (n > 0);
    return sum;
}

int collatz_steps(int n) {
    int steps = 0;
    while (n != 1) {
        if (n % 2 == 0) n /= 2;
        else n = 3 * n + 1;
        steps++;
    }
    return steps;
}
