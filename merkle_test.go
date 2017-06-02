package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func NewTestData() (t [][]byte) {
	t = append(t, []byte("a"))
	t = append(t, []byte("b"))
	t = append(t, []byte("c"))
	t = append(t, []byte("d"))
	return
}

func NewTestDigests() (t [][32]byte) {
	t = append(t, sha256.Sum256([]byte("a")))
	t = append(t, sha256.Sum256([]byte("b")))
	t = append(t, sha256.Sum256([]byte("c")))
	t = append(t, sha256.Sum256([]byte("d")))
	return
}

func TestBuildData(t *testing.T) {
	tree := NewTreeFromData(NewTestData())
	assert.True(t, hex.EncodeToString(tree.Root.Digest[:]) == "14ede5e8e97ad9372327728f5099b95604a39593cac3bd38a343ad76205213e7", "Wrong root calculated from Data")
}

func TestBuildDigests(t *testing.T) {
	tree := NewTreeFromDigests(NewTestDigests())
	assert.True(t, hex.EncodeToString(tree.Root.Digest[:]) == "14ede5e8e97ad9372327728f5099b95604a39593cac3bd38a343ad76205213e7", "Wrong root calculated from Digests")
}

func TestRelationships(t *testing.T) {
	tree := NewTreeFromData(NewTestData())
	assert.True(t, tree.Leaves[0].LeftSide, "Node 0 is left side")
	assert.True(t, tree.Leaves[2].LeftSide, "Node 2 is left side")
	assert.False(t, tree.Leaves[1].LeftSide, "Node 1 is left side")
	assert.False(t, tree.Leaves[3].LeftSide, "Node 3 is left side")
	assert.True(t, tree.Leaves[0].Parent.LeftSide, "Node 0-1 is left side")
}

func TestGetChain(t *testing.T) {
	tree := NewTreeFromData(NewTestData())
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
	controlTree := NewTreeFromData(NewTestData())
	testTree := NewTreeFromData(NewTestData()[0:1])
	testTree.AddAdjust(NewNode([]byte("b")))
	testTree.AddAdjust(NewNode([]byte("c")))
	testTree.AddAdjust(NewNode([]byte("d")))
	assert.True(t, controlTree.Root.Hexdigest() == testTree.Root.Hexdigest(), "Control Tree should have same root val as testTree")

}

func BenchmarkFromDigest(b *testing.B) {
	t := [][32]byte{}
	for i := 0; i < b.N; i++ {
		t = append(t, sha256.Sum256([]byte("a")))
	}
	b.ResetTimer()
	NewTreeFromDigests(t)
}

func BenchmarkAddAdjust(b *testing.B) {
	t := NewTreeFromData(NewTestData()[0:1])
	s := []*Node{}
	for i := 0; i < b.N; i++ {
		s = append(s, NewNode([]byte("a")))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t.AddAdjust(s[i])
	}
}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}
