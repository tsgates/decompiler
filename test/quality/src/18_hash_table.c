/* Test 18: Simple hash table */
#include <stdlib.h>
#include <string.h>

#define TABLE_SIZE 16

typedef struct Entry {
    char key[32];
    int value;
    struct Entry *next;
} Entry;

typedef struct {
    Entry *buckets[TABLE_SIZE];
} HashTable;

unsigned int hash_string(const char *key) {
    unsigned int h = 5381;
    while (*key) {
        h = h * 33 + (unsigned char)*key;
        key++;
    }
    return h % TABLE_SIZE;
}

void ht_init(HashTable *ht) {
    for (int i = 0; i < TABLE_SIZE; i++) {
        ht->buckets[i] = NULL;
    }
}

int ht_set(HashTable *ht, const char *key, int value) {
    unsigned int idx = hash_string(key);
    Entry *e = ht->buckets[idx];
    while (e) {
        if (strcmp(e->key, key) == 0) {
            e->value = value;
            return 0;
        }
        e = e->next;
    }
    e = malloc(sizeof(Entry));
    if (!e) return -1;
    strncpy(e->key, key, 31);
    e->key[31] = '\0';
    e->value = value;
    e->next = ht->buckets[idx];
    ht->buckets[idx] = e;
    return 0;
}

int ht_get(HashTable *ht, const char *key, int *out) {
    unsigned int idx = hash_string(key);
    Entry *e = ht->buckets[idx];
    while (e) {
        if (strcmp(e->key, key) == 0) {
            *out = e->value;
            return 0;
        }
        e = e->next;
    }
    return -1;
}

void ht_free(HashTable *ht) {
    for (int i = 0; i < TABLE_SIZE; i++) {
        Entry *e = ht->buckets[i];
        while (e) {
            Entry *next = e->next;
            free(e);
            e = next;
        }
        ht->buckets[i] = NULL;
    }
}
