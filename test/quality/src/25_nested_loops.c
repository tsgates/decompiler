/* Test 25: Deeply nested loops with complex conditions */

int prime_sieve_count(int *sieve, int n) {
    for (int i = 0; i < n; i++) sieve[i] = 1;
    sieve[0] = sieve[1] = 0;
    for (int i = 2; i * i < n; i++) {
        if (sieve[i]) {
            for (int j = i * i; j < n; j += i)
                sieve[j] = 0;
        }
    }
    int count = 0;
    for (int i = 0; i < n; i++)
        if (sieve[i]) count++;
    return count;
}

void floyd_warshall(int *dist, int n) {
    for (int k = 0; k < n; k++)
        for (int i = 0; i < n; i++)
            for (int j = 0; j < n; j++) {
                int through_k = dist[i * n + k] + dist[k * n + j];
                if (through_k < dist[i * n + j])
                    dist[i * n + j] = through_k;
            }
}

int longest_common_subseq(const char *s1, int len1, const char *s2, int len2, int *dp) {
    for (int i = 0; i <= len1; i++) dp[i * (len2 + 1)] = 0;
    for (int j = 0; j <= len2; j++) dp[j] = 0;
    for (int i = 1; i <= len1; i++)
        for (int j = 1; j <= len2; j++) {
            if (s1[i-1] == s2[j-1])
                dp[i * (len2+1) + j] = dp[(i-1) * (len2+1) + (j-1)] + 1;
            else {
                int a = dp[(i-1) * (len2+1) + j];
                int b = dp[i * (len2+1) + (j-1)];
                dp[i * (len2+1) + j] = a > b ? a : b;
            }
        }
    return dp[len1 * (len2+1) + len2];
}
