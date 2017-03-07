package test_merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"runtime"
	"testing"

	"github.com/jvsteiner/merkle"

	"github.com/stretchr/testify/assert"
)

func NewTestData() (t [][]byte) {
	t = append(t, []byte("a"))
	t = append(t, []byte("b"))
	t = append(t, []byte("c"))
	t = append(t, []byte("d"))
	return
}

func NewTestDigests() (t [][]byte) {
	a := sha256.Sum256([]byte("a"))
	b := sha256.Sum256([]byte("b"))
	c := sha256.Sum256([]byte("c"))
	d := sha256.Sum256([]byte("d"))
	t = append(t, a[:])
	t = append(t, b[:])
	t = append(t, c[:])
	t = append(t, d[:])
	return
}

func TestBuildData(t *testing.T) {
	tree := merkle.NewTreeFromData(NewTestData())
	assert.True(t, hex.EncodeToString(tree.Root.Digest) == "14ede5e8e97ad9372327728f5099b95604a39593cac3bd38a343ad76205213e7", "Wrong root calculated from Data")
}

func TestBuildDigests(t *testing.T) {
	tree := merkle.NewTreeFromDigests(NewTestDigests())
	assert.True(t, hex.EncodeToString(tree.Root.Digest) == "14ede5e8e97ad9372327728f5099b95604a39593cac3bd38a343ad76205213e7", "Wrong root calculated from Digests")
}

func TestRelationships(t *testing.T) {
	tree := merkle.NewTreeFromData(NewTestData())
	assert.True(t, tree.Leaves[0].LeftSide, "Node 0 is left side")
	assert.True(t, tree.Leaves[2].LeftSide, "Node 2 is left side")
	assert.False(t, tree.Leaves[1].LeftSide, "Node 1 is left side")
	assert.False(t, tree.Leaves[3].LeftSide, "Node 3 is left side")
	assert.True(t, tree.Leaves[0].Parent.LeftSide, "Node 0-1 is left side")
}

func TestGetChain(t *testing.T) {
	tree := merkle.NewTreeFromData(NewTestData())
	chain, err := tree.GetChain(0)
	assert.True(t, err == nil, "Single Chain should be returned")
	assert.True(t, len(chain) == 3, "Chain should have length == 3")
	// _, e := fmt.Println(chain)
	// assert.True(t, e == nil, "Single Chain should be serialized")
	chains, err := tree.GetAllChains()
	assert.True(t, err == nil, "Multiple Chains should be returned")
	assert.True(t, len(chains) == 4, "There should be 4 chains")
	// _, er := fmt.Println(chains)
	// assert.True(t, er == nil, "Multiple Chains should be serialized")
}

func TestAddAdjust(t *testing.T) {
	controlTree := merkle.NewTreeFromData(NewTestData())
	testTree := merkle.NewTreeFromData(NewTestData()[0:1])
	testTree.AddAdjust(merkle.NewNode([]byte("b")))
	testTree.AddAdjust(merkle.NewNode([]byte("c")))
	testTree.AddAdjust(merkle.NewNode([]byte("d")))
	assert.True(t, controlTree.Root.Hexdigest() == testTree.Root.Hexdigest(), "Control Tree should have same root val as testTree")

}

func BenchmarkFromDigest(b *testing.B) {
	t := [][]byte{}
	for i := 0; i < b.N; i++ {
		a := sha256.Sum256([]byte("a"))
		t = append(t, a[:])
	}
	b.ResetTimer()
	merkle.NewTreeFromDigests(t)
	b.StopTimer()
}

func BenchmarkAddAdjust(b *testing.B) {
	t := merkle.NewTreeFromData(NewTestData()[0:1])
	s := []*merkle.Node{}
	for i := 0; i < b.N; i++ {
		s = append(s, merkle.NewNode([]byte("a")))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t.AddAdjust(s[i])
	}
	b.StopTimer()
}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}
