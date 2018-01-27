package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
)

type node struct {
	digest              []byte
	leftside            bool
	parent, left, right *node
}

// Tree is the structure. HashFunction is unused currently, but is intended to be used to configure the hash
// algorithm which is used.
type Tree struct {
	mtx          sync.Mutex
	root         *node
	HashFunction string
	leaves       []*node
	size         int
}

func newnode(data []byte) *node {
	digest := sha256.Sum256(data)
	n := &node{digest: digest[:]}
	return n
}

// NewTreeFromDigests constructor can be used when the digests are known for all leaves.
func NewTreeFromDigests(digests [][]byte) *Tree {
	t := &Tree{}
	for i := range digests {
		t.leaves = append(t.leaves, &node{digest: digests[i]})
	}
	t.Build()
	return t
}

// NewTreeFromData constructor for when the data are known for all leaves.
func NewTreeFromData(data [][]byte) *Tree {
	t := &Tree{}
	for i := range data {
		t.leaves = append(t.leaves, newnode(data[i]))
	}
	t.Build()
	return t
}

// Root return the byte slice digest which is the merkle root of the tree
func (t *Tree) Root() []byte {
	return t.root.digest
}

// HexRoot return the hex encoded digest which is the merkle root of the tree
func (t *Tree) HexRoot() string {
	return hex.EncodeToString(t.Root())
}

// Add method to add a node to the leaves, when the digest is known, doesn't recalculate the root.
func (t *Tree) Add(d []byte) {
	t.leaves = append(t.leaves, &node{digest: d})
}

// AddData method to add a node to the leaves, when the data is known, doesn't recalculate the root.
func (t *Tree) AddData(data []byte) {
	t.leaves = append(t.leaves, newnode(data))
}

// Build the tree: call, once the leaves are defined, to calculate the root.
func (t *Tree) Build() []byte {
	t.mtx.Lock()
	defer t.mtx.Unlock()
	if len(t.leaves) == 0 {
		return nil
	}
	layer := t.leaves[:]
	for len(layer) != 1 {
		layer = build(layer)
	}
	t.root = layer[0]
	t.size = len(t.leaves)
	return t.root.digest
}

func build(layer []*node) (newLayer []*node) {
	odd := &node{}
	if len(layer)%2 == 1 {
		odd = layer[len(layer)-1]
		layer = layer[:len(layer)-1]
	}
	for i := 0; i <= len(layer)-1; i += 2 {
		newdigest := sha256.Sum256(append(layer[i].digest[:], layer[i+1].digest[:]...))
		newnode := node{
			digest: newdigest[:],
		}
		newnode.left, newnode.right = layer[i], layer[i+1]
		layer[i].leftside, layer[i+1].leftside = true, false
		layer[i].parent, layer[i+1].parent = &newnode, &newnode
		newLayer = append(newLayer, &newnode)
	}
	if odd.digest != nil {
		newLayer = append(newLayer, odd)
	}
	return
}

// Append adds an additional leaf onto the tree, accepting a digest, and returning the new root
func (t *Tree) Append(digest []byte) []byte {
	t.mtx.Lock()
	return t.append(&node{digest: digest})
}

// AppendData adds an additional leaf onto the tree, accepting data, hashing it, and returning the new root
func (t *Tree) AppendData(data []byte) []byte {
	t.mtx.Lock()
	digest := sha256.Sum256(data)
	return t.append(&node{digest: digest[:]})
}

func (t *Tree) append(n *node) []byte {
	defer t.mtx.Unlock()
	subtrees := t.getWholeSubTrees()
	t.leaves = append(t.leaves, n)
	for i := len(subtrees) - 1; i >= 0; i-- {
		newparent := newnode(append(subtrees[i].digest[:], n.digest[:]...))
		subtrees[i].parent, n.parent = newparent, newparent
		newparent.left, newparent.right = subtrees[i], n
		subtrees[i].leftside, n.leftside = true, false
		n = n.parent
	}
	t.root = n
	t.size++
	return t.root.digest
}

func (t *Tree) getWholeSubTrees() []*node {
	subtrees := []*node{}
	looseleaves := len(t.leaves) - hibit(len(t.leaves))
	thenode := t.root
	for looseleaves != 0 {
		subtrees = append(subtrees, thenode.left)
		thenode = thenode.right
		looseleaves = looseleaves - hibit(looseleaves)
	}
	subtrees = append(subtrees, thenode)
	return subtrees
}

func convert(n *node) *Node {
	return &Node{Digest: n.digest, LeftSide: n.leftside}
}

// GetChain gets the chain, from the leaf at index i, to the root.
func (t *Tree) GetChain(i int) (*Chain, error) {
	chain := &Chain{}
	if i > len(t.leaves)-1 || i < 0 {
		return nil, errors.New("Leaf index does not exist")
	}
	node := t.leaves[i]
	chain.Nodes = append(chain.Nodes, convert(node))
	for node.parent != nil {
		chain.Nodes = append(chain.Nodes, convert(sibling(node)))
		node = node.parent
	}
	chain.Nodes = append(chain.Nodes, convert(node))
	return chain, nil
}

// Leaves return a pointer to a serializable (protobuf) copy of the tree leaves that can be used for persistence
func (t *Tree) Leaves() *Leaves {
	l := &Leaves{Len: int32(len(t.leaves))}
	for _, leaf := range t.leaves {
		l.Digests = append(l.Digests, leaf.digest)
	}
	return l
}

// Rebuild rebuilds a Tree from the Leaves protobuf that contains the leaf digests.
func Rebuild(l *Leaves) *Tree {
	return NewTreeFromDigests(l.Digests)
}

func hashof(s string) []byte {
	digest := sha256.Sum256([]byte(s))
	return digest[:]
}

func sibling(n *node) *node {
	if n.leftside {
		return n.parent.right
	}
	return n.parent.left
}

func hibit(n int) int {
	n |= (n >> 1)
	n |= (n >> 2)
	n |= (n >> 4)
	n |= (n >> 8)
	n |= (n >> 16)
	return n - (n >> 1)
}
