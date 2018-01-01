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
func VerifyChain(c Chain) bool {
	link := c[0].digest
	for i := 1; i < len(c)-1; i++ {
		if c[i].leftSide {
			digest := sha256.Sum256(append(c[i].digest, link...))
			link = digest[:]
		} else {
			digest := sha256.Sum256(append(link, c[i].digest...))
			link = digest[:]
		}
	}
	return bytes.Equal(link, c[len(c)-1].digest)
}

// JoinChains takes two chains from child and parent merkle tree, where the leaves of the parents are roots
// of the children.  By joining the two chains, you are returned a single path through the whole structure.
// This allows larger trees to be split up into smaller pieces, and yet reassembled as needed.
func JoinChains(low, hi Chain) (Chain, error) {
	if !bytes.Equal(low[len(low)-1].digest, hi[0].digest) {
		return nil, errors.New("Chains are not compatible")
	}
	return append(low[0:len(low)-1], hi[1:]...), nil
}
