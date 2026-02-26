/* Test 23: Multi-dimensional arrays and complex indexing */

void init_3d(int *arr, int x, int y, int z) {
    for (int i = 0; i < x; i++)
        for (int j = 0; j < y; j++)
            for (int k = 0; k < z; k++)
                arr[i * y * z + j * z + k] = i + j + k;
}

int sum_2d(int (*arr)[4], int rows) {
    int s = 0;
    for (int i = 0; i < rows; i++)
        for (int j = 0; j < 4; j++)
            s += arr[i][j];
    return s;
}

void diagonal(int *mat, int n, int *diag) {
    for (int i = 0; i < n; i++)
        diag[i] = mat[i * n + i];
}

int count_nonzero(int *arr, int n) {
    int c = 0;
    for (int i = 0; i < n; i++)
        if (arr[i] != 0) c++;
    return c;
}
