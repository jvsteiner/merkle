package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// bigNode element struct, holds digest and number of children, including itself. Represents the root of a
// complete subtree.
type bigNode struct {
	digest []byte
	sumOf  int
}

// BigTree is an optimized merkle tree structure. Only a stack containing complete subtree roots is held in memory.
// BigTreess are more performant at adding new leaves than Trees, and maintain nearly constant memory usage, however
// currently they do not allow the user to retrieve hash chains from them - this feature will be added in the future,
// however, it will inevitably be slower than what is possible for an all-memory tree.
//
// The design goal of BigTree is to provide a cloud scalable merkle tree - one that can facilitate trees with a max
// number of leaves of 18446744073709551615 (max unit64) and still maintain acceptable memory usage, and servicable
// hash chain retrieval times.
type BigTree struct {
	sync.Mutex
	roots *stack
}

// NewBigTree constructs a new BigTree
func NewBigTree() *BigTree {
	return &BigTree{roots: new(stack)}
}

// Append adds an additional leaf onto the bigtree, accepting a digest, and returning the new root
func (t *BigTree) Append(digest []byte) []byte {
	t.Lock()
	n := &bigNode{digest: digest, sumOf: 1}
	return t.append(n)
}

// Append adds an additional leaf onto the bigtree, accepting data, hashing it, and returning the new root
func (t *BigTree) AppendData(data []byte) []byte {
	t.Lock()
	digest := sha256.Sum256(data)
	return t.Append(digest[:])
}

func (t *BigTree) append(n *bigNode) []byte {
	top, ok := t.roots.peek().(*bigNode)
	if !ok {
		t.roots.push(n)
		return t.root()
	}
	summ := top.sumOf + n.sumOf
	if summ&(summ-1) == 0 {
		top = t.roots.pop().(*bigNode)
		n := combine(top, n)
		return t.append(n)
	} else {
		t.roots.push(n)
		return t.root()
	}
}

func combine(l, r *bigNode) *bigNode {
	d := sha256.Sum256(append(l.digest, r.digest...))
	return &bigNode{digest: d[:], sumOf: l.sumOf + r.sumOf}
}

// Root returns the merkle root of a tree - this is calculated upon request, using the stack of whole-subtree merkle roots.
func (t *BigTree) root() []byte {
	defer t.Unlock()
	top := t.roots.head
	if top == nil {
		return nil
	}
	d := top.data.(*bigNode).digest
	for i := top.next; i != nil; i = i.next {
		digest := sha256.Sum256(append(i.data.(*bigNode).digest, d...))
		d = digest[:]
	}
	return d
}

func (t *BigTree) Root() []byte {
	t.Lock()
	return t.root()
}

// HexRoot return the hex encoded digest which is the merkle root of the tree
func (t *BigTree) HexRoot() string {
	return hex.EncodeToString(t.Root())
}
