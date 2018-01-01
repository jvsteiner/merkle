package merkle

import (
	"bytes"
	"crypto/sha256"
)

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
