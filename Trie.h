#include <iostream>
#include <string>
#include <stdio.h>
#include <fstream> //read csv file
#include <vector>
#include <sstream>
#include <map>
#include <unordered_map>

using namespace std;

// TrieNode 구조체
struct TrieNode {
    bool isEndOfWord;
    unordered_map<char, TrieNode*> children;

    TrieNode() : isEndOfWord(false) {}
};


// Trie 클래스
class Trie {

public:
    TrieNode* root;

    Trie() {
        root = new TrieNode();
    }

    ~Trie() {
        deleteNodes(root);
    }

    // 문자열 삽입
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

    // 문자열 검색
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

    // 문자열 삭제
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
