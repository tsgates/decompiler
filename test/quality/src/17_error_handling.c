/* Test 17: Error handling patterns (errno-like, return codes) */
#include <stdlib.h>
#include <string.h>

typedef struct {
    int code;
    char message[64];
} Error;

typedef struct {
    int *data;
    int size;
    int capacity;
} DynArray;

int dynarray_init(DynArray *arr, int capacity) {
    if (capacity <= 0) return -1;
    arr->data = malloc(capacity * sizeof(int));
    if (!arr->data) return -2;
    arr->size = 0;
    arr->capacity = capacity;
    return 0;
}

int dynarray_push(DynArray *arr, int val) {
    if (arr->size >= arr->capacity) {
        int new_cap = arr->capacity * 2;
        int *new_data = realloc(arr->data, new_cap * sizeof(int));
        if (!new_data) return -1;
        arr->data = new_data;
        arr->capacity = new_cap;
    }
    arr->data[arr->size++] = val;
    return 0;
}

int dynarray_get(const DynArray *arr, int index, int *out) {
    if (index < 0 || index >= arr->size) return -1;
    *out = arr->data[index];
    return 0;
}

void dynarray_free(DynArray *arr) {
    free(arr->data);
    arr->data = NULL;
    arr->size = 0;
    arr->capacity = 0;
}

int safe_divide(int a, int b, int *result) {
    if (b == 0) return -1;
    *result = a / b;
    return 0;
}
