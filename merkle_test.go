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
	t = append(t, hashof("a"))
	t = append(t, hashof("b"))
	t = append(t, hashof("c"))
	t = append(t, hashof("d"))
	return
}

func TestBuildData(t *testing.T) {
	tree := NewTreeFromData(NewTestData())
	testval := hex.EncodeToString(tree.Root())
	assert.True(t, testval == "14ede5e8e97ad9372327728f5099b95604a39593cac3bd38a343ad76205213e7", testval)
}

func TestBuildDigests(t *testing.T) {
	tree, err := NewTreeFromDigests(NewTestDigests())
	require.NoError(t, err)
	testval := hex.EncodeToString(tree.Root())
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

func TestAppend(t *testing.T) {
	controlTree := NewTreeFromData(NewTestData())
	testTree := NewTreeFromData(NewTestData()[0:1])
	testTree.Append(hashof("b"))
	testTree.Append(hashof("c"))
	testTree.Append(hashof("d"))
	assert.True(t, controlTree.HexRoot() == testTree.HexRoot(), "Control Tree should have same root val as testTree")
}

func TestBigTree(t *testing.T) {
	controlTree := NewTreeFromData(NewTestData()[0:1])
	testTree := NewBigTree()
	testTree.Append(hashof("a"))
	for i := 0; i < 1000; i++ {
		a := controlTree.Append(hashof("b"))
		b := testTree.Append(hashof("b"))
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

func BenchmarkAppend(b *testing.B) {
	t := NewTreeFromData(NewTestData()[0:1])
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t.Append(hashof("a"))
	}
}

func BenchmarkBigTree(b *testing.B) {
	t := NewBigTree()
	d := hashof("a")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t.Append(d)
	}
}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}
