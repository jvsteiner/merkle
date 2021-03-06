[![Go Report Card](https://goreportcard.com/badge/github.com/jvsteiner/merkle)](https://goreportcard.com/report/github.com/jvsteiner/merkle)
[![GoDoc](https://godoc.org/github.com/jvsteiner/merkle?status.svg)](http://godoc.org/github.com/jvsteiner/merkle)
[![Build Status](https://travis-ci.org/jvsteiner/merkle.png?branch=master)](https://travis-ci.org/jvsteiner/merkle)

# merkle
A Golang implementation of the Merkle/Hash Tree Algorithm

This simple performant implementation is designed to be easily traversible.  The tree has a convenience method for accessing the path from any node to the Merkle root. By using the Append() method, new leaves can be added to an already built tree, without rebuilding.

Installation:

    go get github.com/jvsteiner/merkle

