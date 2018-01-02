package merkle

import (
	"bytes"
	"crypto/sha256"
	"errors"
)

// VerifyChain traveses a path through a merkle tree, validating that the root can correctly be reproduced
// according to the links present.  This function is only used for verifying internal consistency of a chain,
// and so the two ends of the chain must be matched against other anchor points.  Typically, the leaf will
// be verified against some data of interest, and the root against some published root.
func VerifyChain(c *Chain) bool {
	link := c.Nodes[0].Digest
	for i := 1; i < len(c.Nodes)-1; i++ {
		if c.Nodes[i].LeftSide {
			digest := sha256.Sum256(append(c.Nodes[i].Digest, link...))
			link = digest[:]
		} else {
			digest := sha256.Sum256(append(link, c.Nodes[i].Digest...))
			link = digest[:]
		}
	}
	return bytes.Equal(link, c.Nodes[len(c.Nodes)-1].Digest)
}

// JoinChains takes two chains from child and parent merkle tree, where the leaves of the parents are roots
// of the children.  By joining the two chains, you are returned a single path through the whole structure.
// This allows larger trees to be split up into smaller pieces, and yet reassembled as needed.
func JoinChains(low, hi *Chain) (*Chain, error) {
	if !bytes.Equal(low.Nodes[len(low.Nodes)-1].Digest, hi.Nodes[0].Digest) {
		return nil, errors.New("Chains are not compatible")
	}
	joined := &Chain{Nodes: append(low.Nodes[0:len(low.Nodes)-1], hi.Nodes[1:]...)}
	return joined, nil
}
