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
	assert.True(t, tree.leaves[0].leftSide, "Node 0 is left side")
	assert.True(t, tree.leaves[2].leftSide, "Node 2 is left side")
	assert.False(t, tree.leaves[1].leftSide, "Node 1 is left side")
	assert.False(t, tree.leaves[3].leftSide, "Node 3 is left side")
	assert.True(t, tree.leaves[0].parent.leftSide, "Node 0-1 is left side")
}

func TestGetChain(t *testing.T) {
	tree := NewTreeFromData(NewTestData())
	chain, err := tree.GetChain(0)
	assert.True(t, err == nil, "Single Chain should be returned")
	assert.True(t, len(chain) == 4, "Chain should have length == 4")
	assert.True(t, VerifyChain(chain), "chain should verify")
}

func TestJoinChains(t *testing.T) {
	lowtree := NewTreeFromData(NewTestData())
	hiTree := NewTreeFromData(NewTestData()[0:1])
	hiTree.Append(lowtree.Root())
	lowchain, err := lowtree.GetChain(0)
	require.NoError(t, err, "Should be no error")
	hichain, err := hiTree.GetChain(1)
	require.NoError(t, err, "Should be no error")
	joinedChain, err := JoinChains(lowchain, hichain)
	require.NoError(t, err, "Should be no error")
	assert.Equal(t, len(joinedChain), 5, "Chain should have length == 5")
	assert.True(t, VerifyChain(joinedChain), "joined chain should verify")
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
		assert.Equal(t, a, b, "Control Tree should have same root val as Test Tree")
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

func BenchmarkTreeAppend(b *testing.B) {
	t := NewTreeFromData(NewTestData()[0:1])
	d := hashof("a")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t.Append(d)
	}
}

func BenchmarkBigTreeAppend(b *testing.B) {
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
