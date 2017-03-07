package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

type Node struct {
	// Height              int32
	Digest              []byte
	LeftSide            bool
	Parent, Left, Right *Node
}

type HexNode struct {
	Digest string `json:"digest" binding:"required"`
	Left   bool   `json:"left" binding:"required"`
}

func (h Node) String() string {
	s, err := json.Marshal(h.AsHex())
	if err != nil {
		panic(err)
	}
	return string(s)
}

type Tree struct {
	Root         *Node
	HashFunction string
	Leaves       []*Node
}

type Chain []*Node

// func (c Chain) String() string {
// 	s, err := json.Marshal(h.AsHex())
// 	if err != nil {
// 		panic(err)
// 	}
// 	return string(s)
// }

func BitLen(value int) (count uint) {
	count = 0
	for value > 0 {
		count++
		value = value >> 1
	}
	return
}

func NewNode(data []byte) *Node {
	digest := sha256.Sum256(data)
	n := &Node{Digest: digest[:]}
	return n
}

func (n Node) Hexdigest() string {
	return hex.EncodeToString(n.Digest)
}

func (n *Node) AsHex() HexNode {
	h := HexNode{
		Digest: hex.EncodeToString(n.Digest),
		Left:   n.LeftSide,
	}
	return h
}

func NewTreeFromDigests(digests [][]byte) *Tree {
	t := &Tree{}
	for d := range digests {
		t.Leaves = append(t.Leaves, &Node{Digest: digests[d]})
	}
	_, err := t.Build()
	if err != nil {
		panic(err)
	}
	return t
}

func NewTreeFromData(data [][]byte) *Tree {
	t := &Tree{}
	for d := range data {
		t.Leaves = append(t.Leaves, NewNode(data[d]))
	}
	_, err := t.Build()
	if err != nil {
		panic(err)
	}
	return t
}

func Add(t *Tree, d []byte) {
	t.Leaves = append(t.Leaves, &Node{Digest: d})
}

func AddData(t *Tree, data []byte) {
	t.Leaves = append(t.Leaves, NewNode(data))
}

func (t *Tree) Build() ([]byte, error) {
	if len(t.Leaves) == 0 {
		return []byte{}, errors.New("No leaves to build")
	}
	layer := t.Leaves[:]
	for len(layer) != 1 {
		layer = build(layer)
	}
	t.Root = layer[0]
	return t.Root.Digest, nil
}

func build(layer []*Node) (newLayer []*Node) {
	odd := &Node{}
	if len(layer)%2 == 1 {
		odd = layer[len(layer)-1]
		layer = layer[:len(layer)-1]
	}
	for i := 0; i <= len(layer)-1; i = i + 2 {
		newDigest := sha256.Sum256(append(layer[i].Digest, layer[i+1].Digest...))
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

func (t *Tree) AddAdjust(newNode *Node) []byte {
	subtrees := t.getWholeSubTrees()
	t.Leaves = append(t.Leaves, newNode)
	for i := len(subtrees) - 1; i >= 0; i-- {
		newParent := NewNode(append(subtrees[i].Digest, newNode.Digest...))
		subtrees[i].Parent, newNode.Parent = newParent, newParent
		newParent.Left, newParent.Right = subtrees[i], newNode
		subtrees[i].LeftSide, newNode.LeftSide = true, false
		newNode = newNode.Parent
	}
	t.Root = newNode
	return t.Root.Digest
}

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
