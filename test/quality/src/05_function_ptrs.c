/* Test 5: Function pointers and callbacks */
#include <stdlib.h>

typedef int (*comparator)(const void*, const void*);

int int_compare_asc(const void *a, const void *b) {
    return *(const int*)a - *(const int*)b;
}

int int_compare_desc(const void *a, const void *b) {
    return *(const int*)b - *(const int*)a;
}

void sort_ints(int *arr, int n, int ascending) {
    comparator cmp = ascending ? int_compare_asc : int_compare_desc;
    qsort(arr, n, sizeof(int), cmp);
}

typedef struct {
    int (*operate)(int, int);
    const char *name;
} Operation;

int add(int a, int b) { return a + b; }
int sub(int a, int b) { return a - b; }
int mul(int a, int b) { return a * b; }

int apply_op(Operation *op, int x, int y) {
    if (op && op->operate) {
        return op->operate(x, y);
    }
    return 0;
}

int apply_chain(int (**ops)(int, int), int n, int init) {
    int result = init;
    for (int i = 0; i < n; i++) {
        if (ops[i]) {
            result = ops[i](result, i + 1);
        }
    }
    return result;
}
