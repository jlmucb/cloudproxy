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
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = math.Inf

type DirectiveType int32

const (
	DirectiveType_ERROR           DirectiveType = 0
	DirectiveType_FATAL           DirectiveType = 1
	DirectiveType_CREATE_CIRCUIT  DirectiveType = 2
	DirectiveType_DESTROY_CIRCUIT DirectiveType = 3
)

var DirectiveType_name = map[int32]string{
	0: "ERROR",
	1: "FATAL",
	2: "CREATE_CIRCUIT",
	3: "DESTROY_CIRCUIT",
}
var DirectiveType_value = map[string]int32{
	"ERROR":           0,
	"FATAL":           1,
	"CREATE_CIRCUIT":  2,
	"DESTROY_CIRCUIT": 3,
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

type Directive struct {
	Type *DirectiveType `protobuf:"varint,1,req,name=type,enum=mixnet.DirectiveType" json:"type,omitempty"`
	// CREATE_CIRCUIT, a sequence of addresses (e.g. "192.168.1.1:7007")
	// comprising the circuit to be constructed over the mixnet. Each address
	// corresponds to a mixnet router except the last, which is the service the
	// proxy would like to contact.
	Addrs []string `protobuf:"bytes,2,rep,name=addrs" json:"addrs,omitempty"`
	// ERROR or FATAL, an error message.
	Error            *string `protobuf:"bytes,3,opt,name=error" json:"error,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

func (m *Directive) Reset()         { *m = Directive{} }
func (m *Directive) String() string { return proto.CompactTextString(m) }
func (*Directive) ProtoMessage()    {}

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
	proto.RegisterEnum("mixnet.DirectiveType", DirectiveType_name, DirectiveType_value)
}
