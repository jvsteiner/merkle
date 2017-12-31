package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// node element struct, holds digest and relationships
type node struct {
	digest              []byte
	leftSide            bool
	parent, left, right *node
}

// Tree is the structure. Only the root is held, HashFunction is unused currently
type Tree struct {
	root         *node
	HashFunction string
	leaves       []*node
}

// Chain is not much used now, perhaps useful to serialize a chain
type Chain []*node

// Utility function to efficiently calculate the greatest power of 2 less that a given
// integer, more performant by several times than solutions using the math.Log2 function
func hibit(n int) int {
	n |= (n >> 1)
	n |= (n >> 2)
	n |= (n >> 4)
	n |= (n >> 8)
	n |= (n >> 16)
	return n - (n >> 1)
}

// newNode is a constructor for a node, based on underlying data.  For construction based on a precalculated digest
// simply use node := merkle.node{digest: digest[:]} as suggested below.
func newNode(data []byte) *node {
	digest := sha256.Sum256(data)
	n := &node{digest: digest[:]}
	return n
}

// Hexdigest returns the Hex digest of a node
func (n node) Hexdigest() string {
	return hex.EncodeToString(n.digest[:])
}

// NewTreeFromDigests constructor can be used when the digests are known for all leaves.
func NewTreeFromDigests(digests [][]byte) (*Tree, error) {
	t := &Tree{}
	for i := range digests {
		t.leaves = append(t.leaves, &node{digest: digests[i]})
	}
	_, err := t.Build()
	if err != nil {
		return nil, err
	}
	return t, nil
}

// NewTreeFromData constructor for when the data are known for all leaves.
func NewTreeFromData(data [][]byte) *Tree {
	t := &Tree{}
	for i := range data {
		t.leaves = append(t.leaves, newNode(data[i]))
	}
	_, err := t.Build()
	if err != nil {
		panic(err)
	}
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
func (t *Tree) Adddigest(d []byte) {
	t.leaves = append(t.leaves, &node{digest: d})
}

// AddData method to add a node to the leaves, when the data is known, doesn't recalculate the root.
func (t *Tree) AddData(data []byte) {
	t.leaves = append(t.leaves, newNode(data))
}

// Build the tree: call, once the leaves are defined, to calculate the root.
func (t *Tree) Build() ([]byte, error) {
	if len(t.leaves) == 0 {
		return nil, errors.New("No leaves to build")
	}
	layer := t.leaves[:]
	for len(layer) != 1 {
		layer = build(layer)
	}
	t.root = layer[0]
	return t.root.digest, nil
}

// create the tree relationships from a set of leaves, layer by layer
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
		layer[i].leftSide, layer[i+1].leftSide = true, false
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
	return t.append(&node{digest: digest})
}

// AppendData adds an additional leaf onto the tree, accepting data, hashing it, and returning the new root
func (t *Tree) AppendData(data []byte) []byte {
	digest := sha256.Sum256(data)
	return t.append(&node{digest: digest[:]})
}

// Append adds a new node to a calculated tree, efficiently reclaculating the root.
func (t *Tree) append(newnode *node) []byte {
	subtrees := t.getWholeSubTrees()
	t.leaves = append(t.leaves, newnode)
	for i := len(subtrees) - 1; i >= 0; i-- {
		newparent := newNode(append(subtrees[i].digest[:], newnode.digest[:]...))
		subtrees[i].parent, newnode.parent = newparent, newparent
		newparent.left, newparent.right = subtrees[i], newnode
		subtrees[i].leftSide, newnode.leftSide = true, false
		newnode = newnode.parent
	}
	t.root = newnode
	return t.root.digest
}

// return a slice of whole subtrees (number of nodes below are power of 2).
// All trees consist of some number of subtrees.  This is used to recalculate the root
// without recalculating all the hashes.
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

// GetChain gets the chain, from the leaf at index i, to the root.
func (t *Tree) GetChain(i int) (Chain, error) {
	chain := Chain{}
	if i > len(t.leaves)-1 || i < 0 {
		return chain, errors.New("Leaf index does not exist")
	}
	node := t.leaves[i]
	chain = append(chain, node)
	for node.parent != nil {
		chain = append(chain, node.parent)
		node = node.parent
	}
	return chain, nil
}

// GetAllChains gets a slice of chains, one for each leaf, probably could be optimized
// to reduce the number of traversals.
func (t *Tree) GetAllChains() ([]Chain, error) {
	chains := []Chain{}
	for i := 0; i <= len(t.leaves)-1; i++ {
		thisChain, err := t.GetChain(i)
		if err != nil {
			return chains, err
		}
		chains = append(chains, thisChain)
	}
	return chains, nil
}

func hashof(s string) []byte {
	digest := sha256.Sum256([]byte(s))
	return digest[:]
}
