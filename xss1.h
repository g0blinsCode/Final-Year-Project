#include "headers.h"

const int ALPHABET_SIZE = 256;

// Trie node class
class XSSNode {
public:
    bool isEndOfWord;
    vector<XSSNode*> children;

    // Constructor
    XSSNode() {
        isEndOfWord = false;
        children = vector<XSSNode*>(ALPHABET_SIZE, nullptr);
    }
};

// Insert a string into the trie
void insert(XSSNode* root, string key) {
    XSSNode* curr = root;
    for (char c : key) {
        if (!curr->children[c]) {
            curr->children[c] = new XSSNode();
        }
        curr = curr->children[c];
    }
    curr->isEndOfWord = true;
}

// Search for a string in the trie
bool search(XSSNode* root, string key) {
    XSSNode* curr = root;
    for (char c : key) {
        if (!curr->children[c]) {
            return false;
        }
        curr = curr->children[c];
    }
    return curr != nullptr && curr->isEndOfWord;
}
