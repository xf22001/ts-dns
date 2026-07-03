package matcher

import (
	"strings"
	"sync"
)

// trieNode represents a single node in the domain trie.
type trieNode struct {
	children map[string]*trieNode
	isEnd    bool
	isBlock  bool
}

func newTrieNode() *trieNode {
	return &trieNode{children: make(map[string]*trieNode)}
}

// domainTrie is a trie-based matcher for domain names.
type domainTrie struct {
	root *trieNode
	mu   sync.RWMutex
}

func newDomainTrie() *domainTrie {
	return &domainTrie{
		root: newTrieNode(),
	}
}

// Add adds a domain to the trie. Domain parts are processed from right to left (TLD first).
func (t *domainTrie) Add(domain string, isBlock bool) {
	if domain == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	domain = strings.Trim(domain, ".")
	parts := strings.Split(domain, ".")
	node := t.root
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if _, exists := node.children[part]; !exists {
			node.children[part] = newTrieNode()
		}
		node = node.children[part]
	}
	node.isEnd = true
	node.isBlock = isBlock
}

// Match checks if a domain or its parent domains match a rule in the trie.
func (t *domainTrie) Match(domain string) (matched bool, isBlock bool, ok bool) {
	if domain == "" {
		return false, false, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()

	domain = strings.Trim(domain, ".")
	parts := strings.Split(domain, ".")

	// Original logic check:
	// For "test.abc.com", rule ".abc.com" should match.
	// In ABP, ".abc.com" means matching "abc.com" and its subdomains like "test.abc.com".
	// Our trie stores "abc.com". When matching "test.abc.com", we should check:
	// 1. "test.abc.com"
	// 2. "abc.com"
	// 3. "com"

	for i := 0; i < len(parts); i++ {
		node := t.root
		matchFound := true
		for j := len(parts) - 1; j >= i; j-- {
			if next, exists := node.children[parts[j]]; exists {
				node = next
			} else {
				matchFound = false
				break
			}
		}
		if matchFound && node.isEnd {
			return true, node.isBlock, true
		}
	}
	return false, false, false
}

// Walk traverses the trie and calls the provided function for each stored domain.
func (t *domainTrie) Walk(fn func(domain string, isBlock bool)) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	t.walkNode(t.root, []string{}, fn)
}

func (t *domainTrie) walkNode(node *trieNode, parts []string, fn func(domain string, isBlock bool)) {
	if node.isEnd {
		domainParts := make([]string, len(parts))
		for i := 0; i < len(parts); i++ {
			domainParts[len(parts)-1-i] = parts[i]
		}
		fn(strings.Join(domainParts, "."), node.isBlock)
	}
	for part, child := range node.children {
		t.walkNode(child, append(parts, part), fn)
	}
}
