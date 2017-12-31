package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// node element struct, holds digest and relationships
type node struct {
	Digest              []byte `json:"digest" binding:"required"`
	LeftSide            bool   `json:"left" binding:"required"`
	Parent, Left, Right *node
}

// Tree is the structure. Only the root is held, HashFunction is unused currently
type Tree struct {
	root         *node
	HashFunction string
	Leaves       []*node
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
// simply use node := merkle.node{Digest: digest[:]} as suggested below.
func newNode(data []byte) *node {
	digest := sha256.Sum256(data)
	n := &node{Digest: digest[:]}
	return n
}

// Hexdigest returns the Hex digest of a node
func (n node) Hexdigest() string {
	return hex.EncodeToString(n.Digest[:])
}

// NewTreeFromDigests constructor can be used when the digests are known for all leaves.
func NewTreeFromDigests(digests [][]byte) (*Tree, error) {
	t := &Tree{}
	for i := range digests {
		t.Leaves = append(t.Leaves, &node{Digest: digests[i]})
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
		t.Leaves = append(t.Leaves, newNode(data[i]))
	}
	_, err := t.Build()
	if err != nil {
		panic(err)
	}
	return t
}

// Root return the byte slice digest which is the merkle root of the tree
func (t *Tree) Root() []byte {
	return t.root.Digest
}

// HexRoot return the hex encoded digest which is the merkle root of the tree
func (t *Tree) HexRoot() string {
	return hex.EncodeToString(t.Root())
}

// Add method to add a node to the leaves, when the digest is known, doesn't recalculate the root.
func (t *Tree) AddDigest(d []byte) {
	t.Leaves = append(t.Leaves, &node{Digest: d})
}

// AddData method to add a node to the leaves, when the data is known, doesn't recalculate the root.
func (t *Tree) AddData(data []byte) {
	t.Leaves = append(t.Leaves, newNode(data))
}

// Build the tree: call, once the leaves are defined, to calculate the root.
func (t *Tree) Build() ([]byte, error) {
	if len(t.Leaves) == 0 {
		return nil, errors.New("No leaves to build")
	}
	layer := t.Leaves[:]
	for len(layer) != 1 {
		layer = build(layer)
	}
	t.root = layer[0]
	return t.root.Digest, nil
}

// create the tree relationships from a set of leaves, layer by layer
func build(layer []*node) (newLayer []*node) {
	odd := &node{}
	if len(layer)%2 == 1 {
		odd = layer[len(layer)-1]
		layer = layer[:len(layer)-1]
	}
	for i := 0; i <= len(layer)-1; i += 2 {
		newDigest := sha256.Sum256(append(layer[i].Digest[:], layer[i+1].Digest[:]...))
		newnode := node{
			Digest: newDigest[:],
		}
		newnode.Left, newnode.Right = layer[i], layer[i+1]
		layer[i].LeftSide, layer[i+1].LeftSide = true, false
		layer[i].Parent, layer[i+1].Parent = &newnode, &newnode
		newLayer = append(newLayer, &newnode)
	}
	if odd.Digest != nil {
		newLayer = append(newLayer, odd)
	}
	return
}

// Append adds an additional leaf onto the tree, accepting a digest, and returning the new root
func (t *Tree) Append(digest []byte) []byte {
	return t.append(&node{Digest: digest})
}

// AppendData adds an additional leaf onto the tree, accepting data, hashing it, and returning the new root
func (t *Tree) AppendData(data []byte) []byte {
	digest := sha256.Sum256(data)
	return t.append(&node{Digest: digest[:]})
}

// Append adds a new node to a calculated tree, efficiently reclaculating the root.
func (t *Tree) append(newnode *node) []byte {
	subtrees := t.getWholeSubTrees()
	t.Leaves = append(t.Leaves, newnode)
	for i := len(subtrees) - 1; i >= 0; i-- {
		newParent := newNode(append(subtrees[i].Digest[:], newnode.Digest[:]...))
		subtrees[i].Parent, newnode.Parent = newParent, newParent
		newParent.Left, newParent.Right = subtrees[i], newnode
		subtrees[i].LeftSide, newnode.LeftSide = true, false
		newnode = newnode.Parent
	}
	t.root = newnode
	return t.root.Digest
}

// return a slice of whole subtrees (number of nodes below are power of 2).
// All trees consist of some number of subtrees.  This is used to recalculate the root
// without recalculating all the hashes.
func (t *Tree) getWholeSubTrees() []*node {
	subtrees := []*node{}
	looseLeaves := len(t.Leaves) - hibit(len(t.Leaves))
	thenode := t.root
	for looseLeaves != 0 {
		subtrees = append(subtrees, thenode.Left)
		thenode = thenode.Right
		looseLeaves = looseLeaves - hibit(looseLeaves)
	}
	subtrees = append(subtrees, thenode)
	return subtrees
}

// GetChain gets the chain, from the leaf at index i, to the root.
func (t *Tree) GetChain(i int) (Chain, error) {
	chain := Chain{}
	if i > len(t.Leaves)-1 || i < 0 {
		return chain, errors.New("Leaf index does not exist")
	}
	node := t.Leaves[i]
	chain = append(chain, node)
	for node.Parent != nil {
		chain = append(chain, node.Parent)
		node = node.Parent
	}
	return chain, nil
}

// GetAllChains gets a slice of chains, one for each leaf, probably could be optimized
// to reduce the number of traversals.
func (t *Tree) GetAllChains() ([]Chain, error) {
	chains := []Chain{}
	for i := 0; i <= len(t.Leaves)-1; i++ {
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
