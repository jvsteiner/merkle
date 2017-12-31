package merkle

import "crypto/sha256"

// bigNode element struct, holds digest and number of children, including itself. Represents the root of a
// complete subtree.
type bigNode struct {
	digest []byte

	// Represents the number of leaves that this node has under it and summarizes
	sumOf int
}

// BigTree is an optimized merkle tree structure. Only a slice of complete subtree roots is held for
// memory efficiency.
type BigTree struct {
	roots *stack
}

// NewBigTree constructs a new BigTree
func NewBigTree() *BigTree {
	return &BigTree{roots: newStack()}
}

// Append adds an additional leaf onto the bigtree, accepting a digest, and returning the new root
func (t *BigTree) Append(digest []byte) []byte {
	n := &bigNode{digest: digest, sumOf: 1}
	return t.append(n)
}

// Append adds an additional leaf onto the bigtree, accepting data, hashing it, and returning the new root
func (t *BigTree) AppendData(data []byte) []byte {
	digest := sha256.Sum256(data)
	return t.Append(digest[:])
}

func (t *BigTree) append(n *bigNode) []byte {
	top, ok := t.roots.peek().(*bigNode)
	if !ok {
		t.roots.push(n)
		return t.Root()
	}
	summ := top.sumOf + n.sumOf
	if summ&(summ-1) == 0 {
		top = t.roots.pop().(*bigNode)
		n := combine(top, n)
		return t.append(n)
	} else {
		t.roots.push(n)
		return t.Root()
	}
}

func combine(l, r *bigNode) *bigNode {
	d := sha256.Sum256(append(l.digest, r.digest...))
	return &bigNode{digest: d[:], sumOf: l.sumOf + r.sumOf}
}

func (t *BigTree) Root() []byte {
	top := t.roots.first()
	if top == nil {
		return nil
	}
	d := top.Data.(*bigNode).digest
	for i := top.next; i != nil; i = i.next {
		digest := sha256.Sum256(append(i.Data.(*bigNode).digest, d...))
		d = digest[:]
	}
	return d
}
