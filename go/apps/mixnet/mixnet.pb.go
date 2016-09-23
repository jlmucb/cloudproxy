// Code generated by protoc-gen-go.
// source: mixnet.proto
// DO NOT EDIT!

/*
Package mixnet is a generated protocol buffer package.

It is generated from these files:
	mixnet.proto

It has these top-level messages:
	Directive
*/
package mixnet

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

type DirectiveType int32

const (
	DirectiveType_ERROR     DirectiveType = 0
	DirectiveType_CREATE    DirectiveType = 1
	DirectiveType_CREATED   DirectiveType = 2
	DirectiveType_DESTROY   DirectiveType = 3
	DirectiveType_DESTROYED DirectiveType = 4
)

var DirectiveType_name = map[int32]string{
	0: "ERROR",
	1: "CREATE",
	2: "CREATED",
	3: "DESTROY",
	4: "DESTROYED",
}
var DirectiveType_value = map[string]int32{
	"ERROR":     0,
	"CREATE":    1,
	"CREATED":   2,
	"DESTROY":   3,
	"DESTROYED": 4,
}

func (x DirectiveType) Enum() *DirectiveType {
	p := new(DirectiveType)
	*p = x
	return p
}
func (x DirectiveType) String() string {
	return proto.EnumName(DirectiveType_name, int32(x))
}
func (x *DirectiveType) UnmarshalJSON(data []byte) error {
	value, err := proto.UnmarshalJSONEnum(DirectiveType_value, data, "DirectiveType")
	if err != nil {
		return err
	}
	*x = DirectiveType(value)
	return nil
}
func (DirectiveType) EnumDescriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

type Directive struct {
	Type *DirectiveType `protobuf:"varint,1,req,name=type,enum=mixnet.DirectiveType" json:"type,omitempty"`
	// CREATE, a sequence of addresses (e.g. "192.168.1.1:7007")
	// comprising the circuit to be constructed over the mixnet. Each address
	// corresponds to a mixnet router except the last, which is the service the
	// proxy would like to contact.
	Addrs []string `protobuf:"bytes,2,rep,name=addrs" json:"addrs,omitempty"`
	// ERROR or FATAL, an error message.
	Error            *string `protobuf:"bytes,3,opt,name=error" json:"error,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

func (m *Directive) Reset()                    { *m = Directive{} }
func (m *Directive) String() string            { return proto.CompactTextString(m) }
func (*Directive) ProtoMessage()               {}
func (*Directive) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *Directive) GetType() DirectiveType {
	if m != nil && m.Type != nil {
		return *m.Type
	}
	return DirectiveType_ERROR
}

func (m *Directive) GetAddrs() []string {
	if m != nil {
		return m.Addrs
	}
	return nil
}

func (m *Directive) GetError() string {
	if m != nil && m.Error != nil {
		return *m.Error
	}
	return ""
}

func init() {
	proto.RegisterType((*Directive)(nil), "mixnet.Directive")
	proto.RegisterEnum("mixnet.DirectiveType", DirectiveType_name, DirectiveType_value)
}

func init() { proto.RegisterFile("mixnet.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 165 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0xe2, 0xe2, 0xc9, 0xcd, 0xac, 0xc8,
	0x4b, 0x2d, 0xd1, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x62, 0x83, 0xf0, 0x94, 0xfc, 0xb8, 0x38,
	0x5d, 0x32, 0x8b, 0x52, 0x93, 0x4b, 0x32, 0xcb, 0x52, 0x85, 0x94, 0xb9, 0x58, 0x4a, 0x2a, 0x0b,
	0x52, 0x25, 0x18, 0x15, 0x98, 0x34, 0xf8, 0x8c, 0x44, 0xf5, 0xa0, 0x3a, 0xe0, 0x0a, 0x42, 0x2a,
	0x0b, 0x52, 0x85, 0x78, 0xb9, 0x58, 0x13, 0x53, 0x52, 0x8a, 0x8a, 0x25, 0x98, 0x14, 0x98, 0x35,
	0x38, 0x41, 0xdc, 0xd4, 0xa2, 0xa2, 0xfc, 0x22, 0x09, 0x66, 0x05, 0x46, 0x0d, 0x4e, 0x2d, 0x7f,
	0x2e, 0x5e, 0x54, 0xe5, 0x9c, 0x5c, 0xac, 0xae, 0x41, 0x41, 0xfe, 0x41, 0x02, 0x0c, 0x42, 0x5c,
	0x5c, 0x6c, 0xce, 0x41, 0xae, 0x8e, 0x21, 0xae, 0x02, 0x8c, 0x42, 0xdc, 0x5c, 0xec, 0x10, 0xb6,
	0x8b, 0x00, 0x13, 0x88, 0xe3, 0xe2, 0x1a, 0x1c, 0x12, 0xe4, 0x1f, 0x29, 0xc0, 0x2c, 0xc4, 0xcb,
	0xc5, 0x09, 0xe5, 0xb8, 0xba, 0x08, 0xb0, 0x00, 0x02, 0x00, 0x00, 0xff, 0xff, 0xee, 0x98, 0xeb,
	0x06, 0xb7, 0x00, 0x00, 0x00,
}
