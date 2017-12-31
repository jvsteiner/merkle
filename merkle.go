package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// Node element struct, holds digest and relationships
type Node struct {
	Digest              []byte `json:"digest" binding:"required"`
	LeftSide            bool   `json:"left" binding:"required"`
	Parent, Left, Right *Node
}

// Use JSON version to satisfy Stringer interface
func (n Node) String() string {
	s, _ := json.Marshal(n)
	return string(s)
}

// Tree is the structure. Only the root is held, HashFunction is unused currently
type Tree struct {
	Root         *Node
	HashFunction string
	Leaves       []*Node
}

// Chain is not much used now, perhaps useful to serialize a chain
type Chain []*Node

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

// NewNode is a constructor for a Node, based on underlying data.  For construction based on a precalculated digest
// simply use node := merkle.Node{Digest: digest[:]} as suggested below.
func NewNode(data []byte) *Node {
	digest := sha256.Sum256(data)
	n := &Node{Digest: digest[:]}
	return n
}

// Hexdigest returns the Hex digest of a node
func (n Node) Hexdigest() string {
	return hex.EncodeToString(n.Digest[:])
}

// NewTreeFromDigests constructor can be used when the digests are known for all leaves.
func NewTreeFromDigests(digests [][]byte) (*Tree, error) {
	t := &Tree{}
	for i := range digests {
		t.Leaves = append(t.Leaves, &Node{Digest: digests[i]})
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
		t.Leaves = append(t.Leaves, NewNode(data[i]))
	}
	_, err := t.Build()
	if err != nil {
		panic(err)
	}
	return t
}

// Add method to add a node to the leaves, when the digest is known, doesn't recalculate the root.
func (t *Tree) AddDigest(d []byte) {
	t.Leaves = append(t.Leaves, &Node{Digest: d})
}

// AddData method to add a node to the leaves, when the data is known, doesn't recalculate the root.
func (t *Tree) AddData(data []byte) {
	t.Leaves = append(t.Leaves, NewNode(data))
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
	t.Root = layer[0]
	return t.Root.Digest, nil
}

// create the tree relationships from a set of leaves, layer by layer
func build(layer []*Node) (newLayer []*Node) {
	odd := &Node{}
	if len(layer)%2 == 1 {
		odd = layer[len(layer)-1]
		layer = layer[:len(layer)-1]
	}
	for i := 0; i <= len(layer)-1; i += 2 {
		newDigest := sha256.Sum256(append(layer[i].Digest[:], layer[i+1].Digest[:]...))
		newNode := Node{
			Digest: newDigest[:],
		}
		newNode.Left, newNode.Right = layer[i], layer[i+1]
		layer[i].LeftSide, layer[i+1].LeftSide = true, false
		layer[i].Parent, layer[i+1].Parent = &newNode, &newNode
		newLayer = append(newLayer, &newNode)
	}
	if odd.Digest != nil {
		newLayer = append(newLayer, odd)
	}
	return
}

func (t *Tree) Append(digest []byte) []byte {
	return t.append(&Node{Digest: digest})
}

func (t *Tree) AppendData(data []byte) []byte {
	digest := sha256.Sum256(data)
	return t.append(&Node{Digest: digest[:]})
}

// Append adds a new Node to a calculated tree, efficiently reclaculating the root.
func (t *Tree) append(newNode *Node) []byte {
	subtrees := t.getWholeSubTrees()
	t.Leaves = append(t.Leaves, newNode)
	for i := len(subtrees) - 1; i >= 0; i-- {
		newParent := NewNode(append(subtrees[i].Digest[:], newNode.Digest[:]...))
		subtrees[i].Parent, newNode.Parent = newParent, newParent
		newParent.Left, newParent.Right = subtrees[i], newNode
		subtrees[i].LeftSide, newNode.LeftSide = true, false
		newNode = newNode.Parent
	}
	t.Root = newNode
	return t.Root.Digest
}

// return a slice of whole subtrees (number of nodes below are power of 2).
// All trees consist of some number of subtrees.  This is used to recalculate the root
// without recalculating all the hashes.
func (t *Tree) getWholeSubTrees() []*Node {
	subtrees := []*Node{}
	looseLeaves := len(t.Leaves) - hibit(len(t.Leaves))
	theNode := t.Root
	for looseLeaves != 0 {
		subtrees = append(subtrees, theNode.Left)
		theNode = theNode.Right
		looseLeaves = looseLeaves - hibit(looseLeaves)
	}
	subtrees = append(subtrees, theNode)
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
