/* Test 16: 2D array / matrix operations */

void matrix_add(int *result, const int *a, const int *b, int rows, int cols) {
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            result[i * cols + j] = a[i * cols + j] + b[i * cols + j];
        }
    }
}

void matrix_multiply(int *result, const int *a, const int *b, int m, int n, int p) {
    for (int i = 0; i < m; i++) {
        for (int j = 0; j < p; j++) {
            int sum = 0;
            for (int k = 0; k < n; k++) {
                sum += a[i * n + k] * b[k * p + j];
            }
            result[i * p + j] = sum;
        }
    }
}

int matrix_trace(const int *mat, int n) {
    int sum = 0;
    for (int i = 0; i < n; i++) {
        sum += mat[i * n + i];
    }
    return sum;
}

void matrix_transpose(int *result, const int *mat, int rows, int cols) {
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            result[j * rows + i] = mat[i * cols + j];
        }
    }
}
