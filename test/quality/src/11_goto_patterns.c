/* Test 11: Complex control flow with goto-like patterns (early returns, break/continue) */
#include <stddef.h>

int find_first_negative(int *arr, int n) {
    for (int i = 0; i < n; i++) {
        if (arr[i] < 0) return i;
    }
    return -1;
}

int nested_break(int **matrix, int rows, int cols, int target) {
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            if (matrix[i][j] == target)
                return i * cols + j;
        }
    }
    return -1;
}

int count_with_continue(int *arr, int n, int skip_val) {
    int count = 0;
    for (int i = 0; i < n; i++) {
        if (arr[i] == skip_val) continue;
        if (arr[i] < 0) continue;
        count++;
    }
    return count;
}

int multi_return(int x) {
    if (x < 0) return -1;
    if (x == 0) return 0;
    if (x < 10) return 1;
    if (x < 100) return 2;
    if (x < 1000) return 3;
    return 4;
}
