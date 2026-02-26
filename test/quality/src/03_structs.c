/* Test 3: Structs and nested access */
#include <stdio.h>
#include <string.h>

typedef struct {
    int x;
    int y;
} Point;

typedef struct {
    Point center;
    int radius;
} Circle;

typedef struct {
    char name[32];
    int age;
    float score;
} Student;

int point_distance_sq(Point *a, Point *b) {
    int dx = a->x - b->x;
    int dy = a->y - b->y;
    return dx * dx + dy * dy;
}

int circle_area_approx(Circle *c) {
    return 3 * c->radius * c->radius;
}

void student_init(Student *s, const char *name, int age, float score) {
    strncpy(s->name, name, 31);
    s->name[31] = '\0';
    s->age = age;
    s->score = score;
}

int student_compare(const Student *a, const Student *b) {
    if (a->score > b->score) return -1;
    if (a->score < b->score) return 1;
    return strcmp(a->name, b->name);
}

Student* find_best_student(Student *students, int n) {
    if (n <= 0) return NULL;
    Student *best = &students[0];
    for (int i = 1; i < n; i++) {
        if (students[i].score > best->score) {
            best = &students[i];
        }
    }
    return best;
}
