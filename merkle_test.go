package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	t = append(t, a[:])
	b := sha256.Sum256([]byte("b"))
	t = append(t, b[:])
	c := sha256.Sum256([]byte("c"))
	t = append(t, c[:])
	d := sha256.Sum256([]byte("d"))
	t = append(t, d[:])
	return
}

func TestBuildData(t *testing.T) {
	tree := NewTreeFromData(NewTestData())
	testval := hex.EncodeToString(tree.Root.Digest)
	assert.True(t, testval == "14ede5e8e97ad9372327728f5099b95604a39593cac3bd38a343ad76205213e7", testval)
}

func TestBuildDigests(t *testing.T) {
	tree, err := NewTreeFromDigests(NewTestDigests())
	require.NoError(t, err)
	testval := hex.EncodeToString(tree.Root.Digest)
	assert.True(t, testval == "14ede5e8e97ad9372327728f5099b95604a39593cac3bd38a343ad76205213e7", testval)
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
	chains, err := tree.GetAllChains()
	assert.True(t, err == nil, "Multiple Chains should be returned")
	assert.True(t, len(chains) == 4, "There should be 4 chains")
}

func TestAddAdjust(t *testing.T) {
	controlTree := NewTreeFromData(NewTestData())
	testTree := NewTreeFromData(NewTestData()[0:1])
	testTree.AddAdjust(NewNode([]byte("b")))
	testTree.AddAdjust(NewNode([]byte("c")))
	testTree.AddAdjust(NewNode([]byte("d")))
	assert.True(t, controlTree.Root.Hexdigest() == testTree.Root.Hexdigest(), "Control Tree should have same root val as testTree")
}

func TestBigTree(t *testing.T) {
	controlTree := NewTreeFromData(NewTestData()[0:1])
	testTree := NewBigTree()
	testTree.AddDigest(hashof("a"))
	for i := 0; i < 1000; i++ {
		a := controlTree.AddAdjust(NewNode([]byte("b")))
		b := testTree.AddDigest(hashof("b"))
		assert.Equal(t, a, b, "Control Tree should have same root val as testTree")
	}
}

func BenchmarkFromDigest(b *testing.B) {
	t := [][]byte{}
	for i := 0; i < b.N; i++ {
		d := sha256.Sum256([]byte("a"))
		t = append(t, d[:])
	}
	b.ResetTimer()
	NewTreeFromDigests(t)
}

func BenchmarkAddAdjust(b *testing.B) {
	t := NewTreeFromData(NewTestData()[0:1])
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t.AddAdjust(NewNode([]byte("a")))
	}
}

func BenchmarkBigTree(b *testing.B) {
	t := NewBigTree()
	d := sha256.Sum256([]byte("a"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t.AddDigest(d[:])
	}
}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}
