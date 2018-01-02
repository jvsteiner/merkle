// Code generated by protoc-gen-go. DO NOT EDIT.
// source: node.proto

/*
Package merkle is a generated protocol buffer package.

It is generated from these files:
	node.proto

It has these top-level messages:
	Node
	Chain
	Leaves
*/
package merkle

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Node struct {
	Digest   []byte `protobuf:"bytes,1,opt,name=Digest,proto3" json:"Digest,omitempty"`
	LeftSide bool   `protobuf:"varint,2,opt,name=LeftSide" json:"LeftSide,omitempty"`
}

func (m *Node) Reset()                    { *m = Node{} }
func (m *Node) String() string            { return proto.CompactTextString(m) }
func (*Node) ProtoMessage()               {}
func (*Node) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *Node) GetDigest() []byte {
	if m != nil {
		return m.Digest
	}
	return nil
}

func (m *Node) GetLeftSide() bool {
	if m != nil {
		return m.LeftSide
	}
	return false
}

type Chain struct {
	Nodes []*Node `protobuf:"bytes,1,rep,name=Nodes" json:"Nodes,omitempty"`
}

func (m *Chain) Reset()                    { *m = Chain{} }
func (m *Chain) String() string            { return proto.CompactTextString(m) }
func (*Chain) ProtoMessage()               {}
func (*Chain) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *Chain) GetNodes() []*Node {
	if m != nil {
		return m.Nodes
	}
	return nil
}

type Leaves struct {
	Len     int32    `protobuf:"varint,1,opt,name=Len" json:"Len,omitempty"`
	Digests [][]byte `protobuf:"bytes,2,rep,name=Digests,proto3" json:"Digests,omitempty"`
}

func (m *Leaves) Reset()                    { *m = Leaves{} }
func (m *Leaves) String() string            { return proto.CompactTextString(m) }
func (*Leaves) ProtoMessage()               {}
func (*Leaves) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *Leaves) GetLen() int32 {
	if m != nil {
		return m.Len
	}
	return 0
}

func (m *Leaves) GetDigests() [][]byte {
	if m != nil {
		return m.Digests
	}
	return nil
}

func init() {
	proto.RegisterType((*Node)(nil), "merkle.Node")
	proto.RegisterType((*Chain)(nil), "merkle.Chain")
	proto.RegisterType((*Leaves)(nil), "merkle.Leaves")
}

func init() { proto.RegisterFile("node.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 168 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x3c, 0x8e, 0xb1, 0x0a, 0xc2, 0x30,
	0x10, 0x40, 0x49, 0x6b, 0x63, 0x39, 0x3b, 0xc8, 0x0d, 0x12, 0x9c, 0x42, 0xa6, 0x80, 0xd0, 0x41,
	0x9d, 0x5c, 0x75, 0x2c, 0x0e, 0xf1, 0x0b, 0x2a, 0x3d, 0xb5, 0xa8, 0x89, 0x34, 0xc1, 0xef, 0x97,
	0x34, 0xea, 0x76, 0xef, 0x0e, 0xde, 0x3b, 0x00, 0xeb, 0x3a, 0xaa, 0x5f, 0x83, 0x0b, 0x0e, 0xf9,
	0x93, 0x86, 0xfb, 0x83, 0xd4, 0x0e, 0x26, 0x47, 0xd7, 0x11, 0x2e, 0x80, 0x1f, 0xfa, 0x2b, 0xf9,
	0x20, 0x98, 0x64, 0xba, 0x32, 0x5f, 0xc2, 0x25, 0x94, 0x0d, 0x5d, 0xc2, 0xa9, 0xef, 0x48, 0x64,
	0x92, 0xe9, 0xd2, 0xfc, 0x59, 0xad, 0xa0, 0xd8, 0xdf, 0xda, 0xde, 0xa2, 0x82, 0x22, 0x4a, 0xbc,
	0x60, 0x32, 0xd7, 0xb3, 0x75, 0x55, 0x27, 0x79, 0x1d, 0x97, 0x26, 0x9d, 0xd4, 0x16, 0x78, 0x43,
	0xed, 0x9b, 0x3c, 0xce, 0x21, 0x6f, 0xc8, 0x8e, 0x9d, 0xc2, 0xc4, 0x11, 0x05, 0x4c, 0x53, 0xce,
	0x8b, 0x4c, 0xe6, 0xba, 0x32, 0x3f, 0x3c, 0xf3, 0xf1, 0xdb, 0xcd, 0x27, 0x00, 0x00, 0xff, 0xff,
	0xa3, 0xdb, 0x53, 0xcc, 0xbb, 0x00, 0x00, 0x00,
}
