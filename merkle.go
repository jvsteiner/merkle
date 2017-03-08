package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// element struct, holds digest and relationships
type Node struct {
	// Height              int32
	Digest              [32]byte
	LeftSide            bool
	Parent, Left, Right *Node
}

// a serielizable representation of a node for JSON encoding
type HexNode struct {
	Digest string `json:"digest" binding:"required"`
	Left   bool   `json:"left" binding:"required"`
}

// Use JSON version to satisfy Stringer interface
func (h Node) String() string {
	s, err := json.Marshal(h.AsHex())
	if err != nil {
		panic(err)
	}
	return string(s)
}

// only the root is held, HashFunction is unused currently
type Tree struct {
	Root         *Node
	HashFunction string
	Leaves       []*Node
}

// not much used now, perhaps useful to serialize a chain
type Chain []*Node

// func (c Chain) String() string {
// 	s, err := json.Marshal(h.AsHex())
// 	if err != nil {
// 		panic(err)
// 	}
// 	return string(s)
// }

// Utility function to effieciently calculate the max number of bits required to represent an
// integer, more performant by several times than the math.Log2 function
func BitLen(value int) (count uint) {
	count = 0
	for value > 0 {
		count++
		value = value >> 1
	}
	return
}

// Constructor for a Node, based on underlying data.  For construction based on a precalculated digest
// simply use node := merkle.Node{Digest: digest[:]} as suggested below.
func NewNode(data []byte) *Node {
	n := &Node{Digest: sha256.Sum256(data)}
	return n
}

// return the Hex digest of a node
func (n Node) Hexdigest() string {
	return hex.EncodeToString(n.Digest[:])
}

// create a hexified version of the node
func (n *Node) AsHex() HexNode {
	h := HexNode{
		Digest: hex.EncodeToString(n.Digest[:]),
		Left:   n.LeftSide,
	}
	return h
}

// Tree constructor when the digests are known for all leaves.
func NewTreeFromDigests(digests [][32]byte) *Tree {
	t := &Tree{}
	for i := range digests {
		t.Leaves = append(t.Leaves, &Node{Digest: digests[i]})
	}
	_, err := t.Build()
	if err != nil {
		panic(err)
	}
	return t
}

// Tree constructor when the data are known for all leaves.
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

// Method to add a node to the leaves, when the digest is known, doesn't recalculate the root.
func Add(t *Tree, d [32]byte) {
	t.Leaves = append(t.Leaves, &Node{Digest: d})
}

// Method to add a node to the leaves, when the data is known, doesn't recalculate the root.
func AddData(t *Tree, data []byte) {
	t.Leaves = append(t.Leaves, NewNode(data))
}

// call, once the leaves are defined, to calculate the root.
func (t *Tree) Build() ([32]byte, error) {
	if len(t.Leaves) == 0 {
		return [32]byte{}, errors.New("No leaves to build")
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
			Digest: newDigest,
		}
		newNode.Left, newNode.Right = layer[i], layer[i+1]
		layer[i].LeftSide, layer[i+1].LeftSide = true, false
		layer[i].Parent, layer[i+1].Parent = &newNode, &newNode
		newLayer = append(newLayer, &newNode)
	}
	if odd.Digest != [32]byte{} {
		newLayer = append(newLayer, odd)
	}
	return
}

// add a new Node to a calculated tree, efficiently reclaculating the root.
func (t *Tree) AddAdjust(newNode *Node) [32]byte {
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
	// var subtrees []*Node
	subtrees := []*Node{}
	looseLeaves := len(t.Leaves) - (1 << (BitLen(len(t.Leaves)) - 1))
	theNode := t.Root
	for looseLeaves != 0 {
		subtrees = append(subtrees, theNode.Left)
		theNode = theNode.Right
		looseLeaves = looseLeaves - (1 << (BitLen(looseLeaves) - 1))
	}
	subtrees = append(subtrees, theNode)
	return subtrees
}

// Get the chain, from the leaf at index i, to the root.
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

// get a slice of chains, one for each leaf, probably could be optimized
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
