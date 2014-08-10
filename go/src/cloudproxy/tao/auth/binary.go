// Copyright (c) 2014, Kevin Walsh.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

// This file implements Marshal() and Unmarshal() functions for elements. The
// underlying binary format is that of Protobuf. Rather than constructing
// protobuf definitions to hold all of the AST elements, this implementation
// directly invokes primitive encoding and decoding functions within the
// protobuf library.

import (
	"bytes"
	"fmt"

	"code.google.com/p/goprotobuf/proto"
)

// Form is an interface type and so doesn't have a completely natural protobuf
// definition.  For most other elements, there is a natural protobuf definition,
// and it is tempting to use such definitions. For example:
//   message And {
//     repeated Form Conjunct = 1
//   }
//   message Or {
//     repeated Form Disjunct = 1
//   }
// However, this construct would require defining and encoding an extra tag for
// every element, and this inner tag would that effectively duplicates the tag
// from any containing element, in this case the Form variant type. Worse, it
// leads to different encodings for a Form (two tags) and an And (one tag), even
// they are identical formulas.
//
// Instead, we encode all formulas according to the following protobuf
// definition:
//   message Form {
//     optional string pred_name = 1
//     repeated Term pred_arg = 2
//     optional bool const = 3
//     optional Form not = 4
//     repeated Form and = 5
//     repeated Form or = 6
//     optional Form implies_antecedent = 7
//     optional Form implies_consequent = 8
//     optional Prin speaksfor_delegate = 9 // actually, Term
//     optional Prin speaksfor_delegator = 10 // actually, Term
//     optional Prin says_speaker = 11
//     optional int64 says_time = 12
//     optional int64 says_expiration = 13
//     optional Form says_message = 14
//   }
// Alternatively, we can think of Form as a kind of union of the natural
// encodings for each element, where the tags are all chosen to be distinct:
//   message And {
//     repeated Form Conjunct = 5
//   }
//   message Or {
//     repeated Form Disjunct = 6
//   }
//   message Says {
//     required Prin says_speaker = 11 // actually, Term
//     optional int64 says_time = 12
//     optional int64 says_expiration = 13
//     required Form says_message = 14
//   }
//
// Term is encoded as:
//   message Term {
//     optional Prin prin_key = 1
//     repeated PrinExt prin_ext = 2
//     optional string string = 3
//     optional int64 int = 4
//   }
//   message PrinExt {
//     required string ext_name = 5
//     repeated Term ext_arg = 6
//   }

// Term tags
const (
	tagPrinKey = 1 + iota
	tagPrinExt
	tagString
	tagInt
	tagPrinExtName
	tagPrinExtArg
)

// Form tags
const (
	tagPredName = 1 + iota
	tagPredArg
	tagConst
	tagNot
	tagConjunct
	tagDisjunct
	tagImpliesAntecedent
	tagImpliesConsequent
	tagSpeaksforDelegate
	tagSpeaksforDelegator
	tagSaysSpeaker
	tagSaysTime
	tagSaysExpiration
	tagSaysMessage
)

// Note: Error handling is essentially ignored in all of the Marshal functions.
// None of our Marshal functions generate errors, and none of the proto
// functions used generate errors either. The protobuf Marshal functions are all
// declared to return ([]byte, error), but this seems silly, so we just return
// []byte.

// makeKey combines a protobuf tag and wire type into a single "key" value.
func makeKey(uint64 tag, uint64 wireType) uint64 {
	return (tag << 3) | wireType
}

// embed encodes a Form or Term as a tagged, embeded message.
func embed(buf *proto.Buffer, tag uint64, e AuthLogicElement) {
	buf.EncodeVarint(makeKey(tag, proto.WireBytes))
	buf.EncodeRawBytes(e.Marshal())
}

// Marshal encodes a Form or Term as a binary byte array. 
func Marshal(e AuthLogicElement) []byte {
	return e.Marshal()
}

// Marshal encodes a Prin as a binary byte array. 
func (t Prin) Marshal() []byte {
	buf := proto.NewBuffer(nil)
	buf.EncodeVarint(makeKey(tagPrinKey, proto.WireBytes))
	buf.EncodeStringBytes(t.Key)
	for _, e :=  range t.Ext {
		embed(buf, tagPrinExt, e)
	}
	return buf.Bytes()
}

// Marshal encodes a PrinExt as a binary byte array. 
func (t PrinExt) Marshal() []byte {
	buf := proto.NewBuffer(nil)
	buf.EncodeVarint(makeKey(tagPrinExtName, proto.WireBytes))
	buf.EncodeStringBytes(t.Name)
	for _, e :=  range t.Arg {
		embed(buf, tagPrinExtArg, e)
	}
	return buf.Bytes()
}

// Marshal encodes a String as a binary byte array. 
func (t String) Marshal() []byte {
	buf := proto.NewBuffer(nil)
	buf.EncodeVarint(makeKey(tagString, proto.WireBytes))
	buf.EncodeStringBytes(t.(string))
	return buf.Bytes()
}

// Marshal encodes an Int as a binary byte array. 
func (t Int) Marshal() []byte {
	buf := proto.NewBuffer(nil)
	buf.EncodeVarint(makeKey(tagInt, proto.Varint))
	buf.EncodeVarint(t.(int64))
	return buf.Bytes()
}

// Marshal encodes a Pred as a binary byte array. 
func (f Pred) Marshal() []byte {
	buf := proto.NewBuffer(nil)
	buf.EncodeVarint(makeKey(tagPredName, proto.WireBytes))
	buf.EncodeStringBytes(f.Name)
	for _, e :=  range f.Arg {
		embed(buf, tagPredArg, e)
	}
	return buf.Bytes()
}

// Marshal encodes a Const as a binary byte array. 
func (f Const) Marshal() []byte {
	buf := proto.NewBuffer(nil)
	x := 0
	if f.(bool) {
		x = 1
	}
	buf.EncodeVarint(makeKey(tagConst, proto.WireVarint))
	buf.EncodeVarint(1)
	return buf.Bytes()
}

// Marshal encodes a Not as a binary byte array. 
func (f Not) Marshal() []byte {
	buf := proto.NewBuffer(nil)
	embed(buf, tagNot, f.Negand)
	return buf.Bytes()
}

// Marshal encodes an And as a binary byte array. 
func (f And) Marshal() []byte {
	// special case: encode empty conjunct as "true"
	if len(f.Conjunct) == 0) {
		return Const(true).Marshal()
	}
	buf := proto.NewBuffer(nil)
	for _, e := range f.Conjunct {
		embed(buf, tagConjunct, e)
	}
	return buf.Bytes()
}

// Marshal encodes an Or as a binary byte array. 
func (f Or) Marshal() []byte {
	// special case: encode empty disjunct as "false"
	if len(f.Conjunct) == 0) {
		return Const(false).Marshal()
	}
	buf := proto.NewBuffer(nil)
	for _, e := range f.Conjunct {
		embed(buf, tagDisjunct, e)
	}
	return buf.Bytes()
}

// Marshal encodes an Implies as a binary byte array. 
func (f Implies) Marshal() []byte {
	buf := proto.NewBuffer(nil)
	embed(buf, tagImpliesAntecedent, f.Antecedent)
	embed(buf, tagImpliesConsequent, f.Consequent)
	return buf.Bytes()
}

// Marshal encodes a Speaksfor as a binary byte array. 
func (f Speaksfor) Marshal() []byte {
	buf := proto.NewBuffer(nil)
	embed(buf, tagSpeaksforDelegate, f.Delegate)
	embed(buf, tagSpeaksforDelegator, f.Delegator)
	return buf.Bytes()
}

// Marshal encodes a Says as a binary byte array. 
func (f Says) Marshal() []byte {
	buf := proto.NewBuffer(nil)
	embed(buf, tagSaysSpeaker, f.Speaker)
	if f.Commences() {
		buf.EncodeVarint(makeKey(tagSaysTime, proto.WireVarint))
		buf.EncodeVarint(*f.Time)
	}
	if f.Expires() {
		buf.EncodeVarint(makeKey(tagSaysExpiration, proto.WireVarint))
		buf.EncodeVarint(*f.Expiration)
	}
	embed(buf, tagSayMessage, f.Message)
	return buf.Bytes()
}

// todo: Unmarshal
