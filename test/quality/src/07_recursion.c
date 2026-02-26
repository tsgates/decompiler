/* Test 7: Recursion patterns */

int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

int gcd(int a, int b) {
    if (b == 0) return a;
    return gcd(b, a % b);
}

int binary_search(int *arr, int lo, int hi, int target) {
    if (lo > hi) return -1;
    int mid = lo + (hi - lo) / 2;
    if (arr[mid] == target) return mid;
    if (arr[mid] < target)
        return binary_search(arr, mid + 1, hi, target);
    return binary_search(arr, lo, mid - 1, target);
}

int power(int base, int exp) {
    if (exp == 0) return 1;
    if (exp % 2 == 0) {
        int half = power(base, exp / 2);
        return half * half;
    }
    return base * power(base, exp - 1);
}

/* Mutual recursion */
int is_even(int n);
int is_odd(int n);

int is_even(int n) {
    if (n == 0) return 1;
    if (n < 0) n = -n;
    return is_odd(n - 1);
}

int is_odd(int n) {
    if (n == 0) return 0;
    if (n < 0) n = -n;
    return is_even(n - 1);
}
