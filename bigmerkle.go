package merkle

import "crypto/sha256"

// BigNode element struct, holds digest and number of children, including itself. Represents the root of a
// complete subtree.
type BigNode struct {
	Digest []byte `json:"digest" binding:"required"`

	// Represents the number of leaves that this node has under it and threrfore represents
	sumOf int
}

func NewBigNode(d []byte) *BigNode {
	return &BigNode{Digest: d, sumOf: 1}
}

// BigTree is an optimized merkle tree structure. Only a slice of complete subtree roots is held for
// memory efficiency.
type BigTree struct {
	roots *stack
}

func NewBigTree() *BigTree {
	return &BigTree{roots: NewStack()}
}

func (t *BigTree) AddDigest(digest []byte) []byte {
	n := NewBigNode(digest)
	return t.add(n)
}

func (t *BigTree) add(n *BigNode) []byte {
	top, ok := t.roots.Peek().(*BigNode)
	if !ok {
		t.roots.Push(n)
		return t.Root()
	}
	summ := top.sumOf + n.sumOf
	if summ&(summ-1) == 0 {
		top = t.roots.Pop().(*BigNode)
		n := combine(top, n)
		return t.add(n)
	} else {
		t.roots.Push(n)
		return t.Root()
	}
}

func combine(l, r *BigNode) *BigNode {
	d := sha256.Sum256(append(l.Digest, r.Digest...))
	return &BigNode{Digest: d[:], sumOf: l.sumOf + r.sumOf}
}

func (t *BigTree) Root() []byte {
	top := t.roots.First()
	if top == nil {
		return nil
	}
	d := top.Data.(*BigNode).Digest
	for i := top.Next(); i != nil; i = i.Next() {
		digest := sha256.Sum256(append(i.Data.(*BigNode).Digest, d...))
		d = digest[:]
	}
	return d
}

func hashof(s string) []byte {
	digest := sha256.Sum256([]byte(s))
	return digest[:]
}
