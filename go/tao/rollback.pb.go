// Code generated by protoc-gen-go.
// source: proto/rollback.proto
// DO NOT EDIT!

/*
Package tao is a generated protocol buffer package.

It is generated from these files:
	proto/rollback.proto

It has these top-level messages:
	RollbackEntry
	RollbackCounterTable
	RollbackSealedData
*/
package tao

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is the entry used by the host to track the stored counter value.
type RollbackEntry struct {
	HostedProgramName *string `protobuf:"bytes,1,req,name=hosted_program_name" json:"hosted_program_name,omitempty"`
	EntryLabel        *string `protobuf:"bytes,2,req,name=entry_label" json:"entry_label,omitempty"`
	Counter           *int64  `protobuf:"varint,3,opt,name=counter" json:"counter,omitempty"`
	XXX_unrecognized  []byte  `json:"-"`
}

func (m *RollbackEntry) Reset()                    { *m = RollbackEntry{} }
func (m *RollbackEntry) String() string            { return proto.CompactTextString(m) }
func (*RollbackEntry) ProtoMessage()               {}
func (*RollbackEntry) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *RollbackEntry) GetHostedProgramName() string {
	if m != nil && m.HostedProgramName != nil {
		return *m.HostedProgramName
	}
	return ""
}

func (m *RollbackEntry) GetEntryLabel() string {
	if m != nil && m.EntryLabel != nil {
		return *m.EntryLabel
	}
	return ""
}

func (m *RollbackEntry) GetCounter() int64 {
	if m != nil && m.Counter != nil {
		return *m.Counter
	}
	return 0
}

// Table of entries.
type RollbackCounterTable struct {
	Entries          []*RollbackEntry `protobuf:"bytes,1,rep,name=entries" json:"entries,omitempty"`
	XXX_unrecognized []byte           `json:"-"`
}

func (m *RollbackCounterTable) Reset()                    { *m = RollbackCounterTable{} }
func (m *RollbackCounterTable) String() string            { return proto.CompactTextString(m) }
func (*RollbackCounterTable) ProtoMessage()               {}
func (*RollbackCounterTable) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *RollbackCounterTable) GetEntries() []*RollbackEntry {
	if m != nil {
		return m.Entries
	}
	return nil
}

// This is the data structure sealed by the host.
type RollbackSealedData struct {
	Entry            *RollbackEntry `protobuf:"bytes,1,opt,name=entry" json:"entry,omitempty"`
	ProtectedData    []byte         `protobuf:"bytes,2,opt,name=protected_data" json:"protected_data,omitempty"`
	XXX_unrecognized []byte         `json:"-"`
}

func (m *RollbackSealedData) Reset()                    { *m = RollbackSealedData{} }
func (m *RollbackSealedData) String() string            { return proto.CompactTextString(m) }
func (*RollbackSealedData) ProtoMessage()               {}
func (*RollbackSealedData) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *RollbackSealedData) GetEntry() *RollbackEntry {
	if m != nil {
		return m.Entry
	}
	return nil
}

func (m *RollbackSealedData) GetProtectedData() []byte {
	if m != nil {
		return m.ProtectedData
	}
	return nil
}

func init() {
	proto.RegisterType((*RollbackEntry)(nil), "tao.rollback_entry")
	proto.RegisterType((*RollbackCounterTable)(nil), "tao.rollback_counter_table")
	proto.RegisterType((*RollbackSealedData)(nil), "tao.rollback_sealed_data")
}

/*
var fileDescriptor0 = []byte{
	// 197 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0x74, 0x8f, 0xc1, 0x6a, 0x84, 0x30,
	0x10, 0x86, 0x89, 0xa1, 0x48, 0xc7, 0x62, 0x21, 0x8a, 0x08, 0xbd, 0x48, 0xe8, 0x21, 0x27, 0x0b,
	0x7d, 0x80, 0x3e, 0x44, 0xfb, 0x00, 0x61, 0xd4, 0xa1, 0x2d, 0x8d, 0xa6, 0xc4, 0xd9, 0xc3, 0xbe,
	0xfd, 0xc6, 0xe0, 0x0a, 0x7b, 0xd8, 0x63, 0xfe, 0xfc, 0xdf, 0xcf, 0x37, 0x50, 0xff, 0x07, 0xcf,
	0xfe, 0x2d, 0x78, 0xe7, 0x06, 0x1c, 0xff, 0xfa, 0xf4, 0x54, 0x92, 0xd1, 0xeb, 0x2f, 0x28, 0xaf,
	0xb1, 0xa5, 0x85, 0xc3, 0x59, 0xbd, 0x40, 0xf5, 0xe3, 0x57, 0xa6, 0xc9, 0xc6, 0xda, 0x77, 0xc0,
	0xd9, 0x2e, 0x38, 0x53, 0x2b, 0xba, 0xcc, 0x3c, 0xaa, 0x0a, 0x8a, 0xd4, 0xb2, 0x0e, 0x07, 0x72,
	0x6d, 0x96, 0xc2, 0x67, 0xc8, 0x47, 0x7f, 0x5a, 0x98, 0x42, 0x2b, 0x3b, 0x61, 0xa4, 0xfe, 0x80,
	0xe6, 0x18, 0xdd, 0x7f, 0x2c, 0xe3, 0xe0, 0x48, 0xbd, 0x42, 0xbe, 0xf1, 0xbf, 0xb4, 0xc6, 0x41,
	0x69, 0x8a, 0xf7, 0xaa, 0x8f, 0x16, 0xfd, 0xad, 0x82, 0xfe, 0x84, 0xfa, 0x48, 0x56, 0x42, 0x17,
	0x5d, 0x26, 0x64, 0x54, 0x1a, 0x1e, 0x52, 0x21, 0xb2, 0xe2, 0x0e, 0xab, 0x1a, 0x28, 0xb7, 0xf3,
	0x68, 0xe4, 0x9d, 0x8a, 0x92, 0xc2, 0x3c, 0x5d, 0x02, 0x00, 0x00, 0xff, 0xff, 0x00, 0x0a, 0x5b,
	0xae, 0x04, 0x01, 0x00, 0x00,
}
 */
