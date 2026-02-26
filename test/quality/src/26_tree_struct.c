/* Test 26: Tree data structure */
#include <stdlib.h>

typedef struct TreeNode {
    int key;
    struct TreeNode *left;
    struct TreeNode *right;
} TreeNode;

TreeNode* tree_insert(TreeNode *root, int key) {
    if (!root) {
        TreeNode *n = malloc(sizeof(TreeNode));
        if (n) { n->key = key; n->left = n->right = NULL; }
        return n;
    }
    if (key < root->key) root->left = tree_insert(root->left, key);
    else if (key > root->key) root->right = tree_insert(root->right, key);
    return root;
}

TreeNode* tree_find(TreeNode *root, int key) {
    while (root) {
        if (key == root->key) return root;
        if (key < root->key) root = root->left;
        else root = root->right;
    }
    return NULL;
}

int tree_height(TreeNode *root) {
    if (!root) return 0;
    int lh = tree_height(root->left);
    int rh = tree_height(root->right);
    return 1 + (lh > rh ? lh : rh);
}

int tree_count(TreeNode *root) {
    if (!root) return 0;
    return 1 + tree_count(root->left) + tree_count(root->right);
}
