#include <iostream>
#include <string>
#include <stdio.h>
#include <fstream> //read csv file
#include <vector>
#include <sstream>
#include <map>
#include <unordered_map>

using namespace std;

// TrieNode ����ü
struct TrieNode {
    bool isEndOfWord;
    unordered_map<char, TrieNode*> children;

    TrieNode() : isEndOfWord(false) {}
};


// Trie Ŭ����
class Trie {

public:
    TrieNode* root;

    Trie() {
        root = new TrieNode();
    }

    ~Trie() {
        deleteNodes(root);
    }

    // ���ڿ� ����
    void insert(const std::string& word) {
        TrieNode* current = root;
        for (char c : word) {
            if (current->children.find(c) == current->children.end()) {
                current->children[c] = new TrieNode();
            }
            current = current->children[c];
        }
        current->isEndOfWord = true;
    }

    // ���ڿ� �˻�
    bool search(const std::string& word) {
        TrieNode* current = root;
        for (char c : word) {
            if (current->children.find(c) == current->children.end()) {
                return false;
            }
            current = current->children[c];
        }
        return current->isEndOfWord;
    }

    // ���ڿ� ����
    void remove(const std::string& word) {
        removeHelper(root, word, 0);
    }

    void deleteNodes(TrieNode* node) {
        if (node == nullptr) return;
        for (auto& pair : node->children) {
            deleteNodes(pair.second);
        }
        delete node;
    }

    bool removeHelper(TrieNode* node, const string& word, int depth) {
        if (depth == word.length()) {
            if (!node->isEndOfWord) return false;
            node->isEndOfWord = false;
            return node->children.empty();
        }

        char c = word[depth];
        if (node->children.find(c) == node->children.end()) {
            return false;
        }

        bool shouldDeleteNode = removeHelper(node->children[c], word, depth + 1);

        if (shouldDeleteNode) {
            delete node->children[c];
            node->children.erase(c);
            return node->children.empty();
        }

        return false;
    }
};
