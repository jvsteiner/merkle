[![Go Report Card](https://goreportcard.com/badge/github.com/jvsteiner/merkle)](https://goreportcard.com/report/github.com/jvsteiner/merkle)

# merkle
A Golang implementation of the Merkle/Hash Tree Algorithm

This simple performant implementation is designed to be easily traversible.  The tree has a convenience method for accessing the path from any node to the Merkle root. By using the AddAdjust() method, new leaves can be added to an already built tree, without rebuilding.

Installation:

    go get github.com/jvsteiner/merkle

