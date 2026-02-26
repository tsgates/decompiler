/* Test 9: Complex nested structs and unions */
#include <string.h>

typedef enum { SHAPE_CIRCLE, SHAPE_RECT, SHAPE_TRIANGLE } ShapeType;

typedef struct {
    int radius;
} CircleData;

typedef struct {
    int width;
    int height;
} RectData;

typedef struct {
    int base;
    int height;
} TriangleData;

typedef struct {
    ShapeType type;
    union {
        CircleData circle;
        RectData rect;
        TriangleData triangle;
    } data;
    int color;
} Shape;

int shape_area(const Shape *s) {
    switch (s->type) {
        case SHAPE_CIRCLE:
            return 3 * s->data.circle.radius * s->data.circle.radius;
        case SHAPE_RECT:
            return s->data.rect.width * s->data.rect.height;
        case SHAPE_TRIANGLE:
            return s->data.triangle.base * s->data.triangle.height / 2;
        default:
            return 0;
    }
}

int compare_shapes(const Shape *a, const Shape *b) {
    int area_a = shape_area(a);
    int area_b = shape_area(b);
    if (area_a > area_b) return 1;
    if (area_a < area_b) return -1;
    return 0;
}

typedef struct {
    Shape shapes[8];
    int count;
    char name[16];
} Canvas;

int canvas_total_area(const Canvas *c) {
    int total = 0;
    for (int i = 0; i < c->count && i < 8; i++) {
        total += shape_area(&c->shapes[i]);
    }
    return total;
}

void canvas_init(Canvas *c, const char *name) {
    memset(c, 0, sizeof(Canvas));
    strncpy(c->name, name, 15);
    c->name[15] = '\0';
}
