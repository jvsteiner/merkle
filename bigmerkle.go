package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// BigTree is an optimized Merkle tree structure. Only a stack containing complete subtree roots is held in memory.
// BigTrees are more performant at adding new leaves than Trees, and maintain nearly constant memory usage, however
// currently they do not allow the user to retrieve hash chains from them - this feature will be added in the future,
// however, it will inevitably be slower than what is possible for an all-memory tree.
//
// The design goal of BigTree is to provide a cloud scalable Merkle tree - one that can facilitate trees with a max
// number of leaves of 18446744073709551615 (max unit64) and still maintain acceptable memory usage, and serviceable
// hash chain retrieval times.
type BigTree struct {
	mtx            sync.Mutex
	roots          *stack
	maxsubtreesize int
}

// NewBigTree constructs a new, empty BigTree where the subtrees are of max size 2^power.  power = 8-16 are reasonable
// values to reduce memory usage.
func NewBigTree(power uint8) *BigTree {
	return &BigTree{roots: new(stack), maxsubtreesize: 1 << power}
}

// Append adds an additional leaf onto the BigTree, accepting a digest, and returning the new root
func (bt *BigTree) Append(digest []byte) []byte {
	n := NewTreeFromDigests([][]byte{digest})
	bt.mtx.Lock()
	return bt.append(n)
}

// Append adds an additional leaf onto the BigTree, accepting data, hashing it, and returning the new root
func (bt *BigTree) AppendData(data []byte) []byte {
	digest := sha256.Sum256(data)
	return bt.Append(digest[:])
}

// HexRoot return the hex encoded digest which is the Merkle root of the tree
func (bt *BigTree) HexRoot() string {
	return hex.EncodeToString(bt.Root())
}

// Root returns the root digest of the Tree
func (bt *BigTree) Root() []byte {
	bt.mtx.Lock()
	return bt.root()
}

func (bt *BigTree) append(t *Tree) []byte {
	top, ok := bt.roots.peek().(*Tree)
	if !ok {
		bt.roots.push(t)
		return bt.root()
	}
	newsize := top.size + t.size
	if newsize&(newsize-1) == 0 {
		top = bt.roots.pop().(*Tree)
		t := combine(top, t)
		switch {
		case len(t.leaves) == bt.maxsubtreesize:
			t = reduce(t)
		case len(t.leaves) > bt.maxsubtreesize:
			panic("shouldn't happen")
		}
		return bt.append(t)
	} else {
		bt.roots.push(t)
		return bt.root()
	}
}

func reduce(t *Tree) *Tree {
	reduced := NewTreeFromDigests([][]byte{t.root.digest})
	reduced.size = t.size
	return reduced
}

func combine(l, r *Tree) *Tree {
	l.leaves = append(l.leaves, r.leaves...)
	d := sha256.Sum256(append(l.root.digest, r.root.digest...))
	newroot := &node{digest: d[:], left: l.root, right: r.root}
	l.root.parent, r.root.parent = newroot, newroot
	l.root.leftside, r.root.leftside = true, false
	l.root = newroot
	l.size += r.size
	return l
}

func (bt *BigTree) root() []byte {
	defer bt.mtx.Unlock()
	top := bt.roots.head
	if top == nil {
		return nil
	}
	d := top.data.(*Tree).root.digest
	for i := top.next; i != nil; i = i.next {
		digest := sha256.Sum256(append(i.data.(*Tree).root.digest, d...))
		d = digest[:]
	}
	return d
}
