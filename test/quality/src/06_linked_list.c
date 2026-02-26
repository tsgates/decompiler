/* Test 6: Linked list operations */
#include <stdlib.h>

typedef struct Node {
    int data;
    struct Node *next;
} Node;

Node* node_create(int data) {
    Node *n = malloc(sizeof(Node));
    if (n) {
        n->data = data;
        n->next = NULL;
    }
    return n;
}

void list_push(Node **head, int data) {
    Node *n = node_create(data);
    if (n) {
        n->next = *head;
        *head = n;
    }
}

int list_pop(Node **head) {
    if (!*head) return -1;
    Node *tmp = *head;
    int data = tmp->data;
    *head = tmp->next;
    free(tmp);
    return data;
}

int list_length(Node *head) {
    int count = 0;
    while (head) {
        count++;
        head = head->next;
    }
    return count;
}

Node* list_reverse(Node *head) {
    Node *prev = NULL;
    while (head) {
        Node *next = head->next;
        head->next = prev;
        prev = head;
        head = next;
    }
    return prev;
}

Node* list_find(Node *head, int data) {
    while (head) {
        if (head->data == data) return head;
        head = head->next;
    }
    return NULL;
}

void list_free(Node *head) {
    while (head) {
        Node *next = head->next;
        free(head);
        head = next;
    }
}
