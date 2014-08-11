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
// None of our Marshal functions generate errors. None of the proto Marshal
// functions generate errors either, despite beging declared to return ([]byte,
// error). Our Marshal functions simply return []byte.

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
	buf.EncodeVarint(x)
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

// varintEOF is a hack to detect EOF in a proto.Buffer.
const varintEOF = 0

// newBufferWithEOF returns a proto.Buffer for reading with an EOF at the end.
func newBufferWithEOF(bytes []byte) proto.Buffer {
	// Hack: append a special EOF mark in the array, using (illegal) tag 0.
	// Sadly, this means we can't do in-place decoding.
	copied = append(append([]byte, bytes...), varintEOF)
	return proto.NewBuffer(copied)
}

// UnmarshalTerm decodes a Term from a binary byte array. 
func UnmarshalTerm(bytes []byte) (Term, error) {
	buf := newBufferWithEOF(bytes)
	key, err := buf.DecodeVarint()
	if err != nil {
		return nil, err
	}
	switch key {
	case varintEOF:
		return nil, io.ErrUnexpectedEOF
	case makeKey(tagString, proto.WireBytes):
		s, err := buf.DecodeStringBytes()
		if err != nil {
			return nil, err
		}
		t = String(s)
		key, err = buf.DecodeVarint()  // should be EOF
	case makeKey(tagInt, proto.WireBytes):
		i, err := buf.DecodeVarint()
		if err != nil {
			return nil, err
		}
		t = Int(i)
		key, err = buf.DecodeVarint()  // should be EOF
	case makeKey(tagPrinKey, proto.WireBytes):
	case makeKey(tagPrinExt, proto.WireBytes):
		prin := Prin{}
		haveKey := false
		for err != nil && key != int64(varintEOF) {
			if key == makeKey(tagPrinKey, proto.WireBytes) {
				if haveKey {
					return nil, errors.New("duplicate key in marshalled Prin")
				}
				haveKey = true
				prin.Key, err = buf.DecodeStringBytes()
				if err != nil {
					return nil, err
				}
			} else if key == makeKey(tagPrinExt, proto.WireBytes) {
				// alloc=false since we copy in unmarshalNameAndArgs()
				embedded, err := buf.DecodeRawBytes(false)
				if err {
					return nil, err
				}
				name, args, err := unmarshalNameAndArgs(embedded, tagPrinExtName, tagPrinExtArg)
				if err {
					return nil, err
				}
				prin.Ext = append(prin.Ext, PrinExt{name, args})
			} else {
				return nil, fmt.Errorf("unexpected key in marshalled Prin: %d", key)
			}
			key, err = buf.DecodeVarint()
		}
		t = prin
	default:
		return nil, fmt.Errorf("unexpected key in marshalled Prin: %d", key)
	}
	if err != nil {
		return nil, err
	}
	if !haveKey {
		return "", nil, fmt.Errorf("missing key in marshalled Pred or PrinExt")
	}
	if key != varintEOF {
		return nil, fmt.Errorf("extra trailing key in marshalled Prin: %d", key)
	}
	return t
}

// unmarshalNameAndArgs decodes a name and zero or more Term args.
func unmarshalNameAndArgs(bytes []byte, tagName, tagArgs) (name string, args []Term , err error) {
	buf := newBufferWithEOF(bytes)
	key, err := buf.DecodeVarint()
	if err != nil {
		return "", nil, err
	}
	haveName := false
	for key, err := buf.DecodeVarint(); err != nil && key != varintEOF {
		switch key {
		case makeKey(tagName, proto.WireBytes):
			if haveName {
				return "", nil, errors.New("duplicate name in marshalled Pred or PrinExt")
			}
			haveName = true
			name, err := buf.DecodeStringBytes()
			if err != nil {
				return "", nil, err
			}
		case makeKey(tagArg, proto.WireBytes):
			// alloc=false since we copy in unmarshalNameAndArgs()
			embedded, err := buf.DecodeRawBytes(false)
			if err {
				return "", nil, err
			}
			arg, err := UnmarshalTerm(embedded)
			if err {
				return "", nil, err
			}
			args = append(args, arg)
		default:
			return "", nil, fmt.Errorf("unexpected key in marshalled Pred or PrinExt: %d", key)
		}
	}
	if err != nil {
		return "", nil, err
	}
	if !haveName {
		return "", nil, fmt.Errorf("missing name in marshalled Pred or PrinExt")
	}
	if key != varintEOF {
		return "", nil, fmt.Errorf("extra trailing key in marshalled Prin: %d", key)
	}
	return name, args, nil
}

// UnmarshalForm decodes a Form from a binary byte array. 
func UnmarshalTerm(bytes []byte) (Form, error) {
	buf := proto.NewBuffer(bytes)
	key, err := buf.DecodeVarint()
	if err != nil {
		return nil, err
	}
	switch key {
	case tagPredName:
	case tagPredArg:
		return unmarshalPred(bytes)
	case tagConst:
		return unmarshalConst(bytes)
	case tagNot:
		return unmarshalNot(bytes)
	case tagConjunct:
		return unmarshalAnd(bytes)
	case tagDisjunct:
		return unmarshalOr(bytes)
	case tagImpliesAntecedent:
	case tagImpliesConsequent:
		return unmarshalImplies(bytes)
	case tagSpeaksforDelegate:
	case tagSpeaksforDelegator:
		return unmarshalSpeaksfor(bytes)
	case tagSaysSpeaker:
	case tagSaysTime:
	case tagSaysExpiration:
	case tagSaysMessage:
		return unmarshalSays(bytes)
	default:
		return nil, fmt.Errorf("unexpected key in marshalled Form: %d", key)
	}
}

// unmarshalPred decodes a Pred from a binary byte array.
func unmarshalPred(bytes []byte) (Pred, error) {
	name, args, err := unmarshalNameAndArgs(bytes, tagPredName, tagPredArg)
	return Pred{name, args}, err
}

// unmarshalConst decodes a Const from a binary byte array.
func unmarshalConst(bytes []byte) (Const, error) {
	buf := newBufferWithEOF(bytes)
	key, err := buf.DecodeVarint()
	if err != nil {
		return nil, err
	}
	if key != makeKey(tagConst, proto.WireVarint) {
		return Const(false), fmt.Errorf("unexpected key in marshalled Const: %d", key)
	}
	x, err := buf.DecodeVarint()
	if x != 0 && x != 1 {
		return Const(false), fmt.Errorf("unexpected value in marshalled Const: %d", x)
	}
	eof, err := buf.DecodeVarint()
	if err != nil {
		return nil, err
	}
	if key != varintEOF {
		return Const(false), fmt.Errorf("extra trailing key in marshalled Const: %d", key)
	}
	return Const(x == 1), nil
}

// unmarshalNot decodes a Not from a binary byte array.
func unmarshalNot(bytes []byte) (Not, error) {
	buf := newBufferWithEOF(bytes)
	key, err := buf.DecodeVarint()
	if err != nil {
		return nil, err
	}
	if key != makeKey(tagNot, proto.WireBytes) {
		return Not{}, fmt.Errorf("unexpected key in marshalled Not: %d", key)
	}
	embedded, err := buf.DecodeRawBytes(false)
	if err {
		return Not{}, err
	}
	f, err := UnmarshalForm(embedded)
	if err {
		return Not{}, err
	}
	eof, err := buf.DecodeVarint()
	if err != nil {
		return Not{}, err
	}
	if key != varintEOF {
		return Not{}, fmt.Errorf("extra trailing key in marshalled Not: %d", key)
	}
	return Not{f}, nil
}

// unmarshalAnd decodes an And from a binary byte array.
func unmarshalAnd(bytes []byte) (And, error) {
	buf := newBufferWithEOF(bytes)
	var and And
	for key, err := buf.DecodeVarint(); err != nil && key != varintEOF {
		if key != makeKey(tagConjunct, proto.WireBytes) {
			return And{}, fmt.Errorf("unexpected key in marshalled And: %d", key)
		}
		embedded, err := buf.DecodeRawBytes(false)
		if err {
			return And{}, err
		}
		f, err := UnmarshalForm(embedded)
		if err {
			return And{}, err
		}
		and.Conjunct = append(and.Conjunct, f)
	}
	if err != nil {
		return And{}, err
	}
	if key != varintEOF {
		return And{}, fmt.Errorf("extra trailing key in marshalled And: %d", key)
	}
	return and, nil
}

// unmarshalOr decodes an Or from a binary byte array.
func unmarshalOr(bytes []byte) (Or, error) {
	buf := newBufferWithEOF(bytes)
	var or Or
	for key, err := buf.DecodeVarint(); err != nil && key != varintEOF {
		if key != makeKey(tagDisjunct, proto.WireBytes) {
			return Or{}, fmt.Errorf("unexpected key in marshalled Or: %d", key)
		}
		embedded, err := buf.DecodeRawBytes(false)
		if err {
			return Or{}, err
		}
		f, err := UnmarshalForm(embedded)
		if err {
			return Or{}, err
		}
		or.Disjunct = append(or.Disjunct, f)
	}
	if err != nil {
		return Or{}, err
	}
	if key != varintEOF {
		return Or{}, fmt.Errorf("extra trailing key in marshalled Or: %d", key)
	}
	return or, nil
}

// unmarshalImplies decodes an Implies from a binary byte array.
func unmarshalImplies(bytes []byte) (Implies, error) {
	buf := newBufferWithEOF(bytes)
	var implies Implies
	for key, err := buf.DecodeVarint(); err != nil && key != varintEOF {
		if key == makeKey(tagImpliesAntecedent, proto.WireBytes) {
			if implies.Antecedent != nil {
				return Implies{}, errors.New("duplicate antecedent in marshalled Implies")
			}
			embedded, err := buf.DecodeRawBytes(false)
			if err {
				return Implies{}, err
			}
			f, err := UnmarshalForm(embedded)
			if err {
				return Implies{}, err
			}
			implies.Antecedent = f
		} else if key == makeKey(tagImpliesConsequent, proto.WireBytes) {
			if implies.Consequent != nil {
				return Implies{}, errors.New("duplicate consequent in marshalled Implies")
			}
			embedded, err := buf.DecodeRawBytes(false)
			if err {
				return Implies{}, err
			}
			f, err := UnmarshalForm(embedded)
			if err {
				return Implies{}, err
			}
			implies.Consequent = f
		} else {
			return Implies{}, fmt.Errorf("unexpected key in marshalled Implies: %d", key)
		}
	}
	if err != nil {
		return Implies{}, err
	}
	if key != varintEOF {
		return Implies{}, fmt.Errorf("extra trailing key in marshalled Implies: %d", key)
	}
	return implies, nil
}

// unmarshalImplies decodes an Implies from a binary byte array.
func unmarshalImplies(bytes []byte) (Implies, error) {
	buf := newBufferWithEOF(bytes)
	var implies Implies
	for key, err := buf.DecodeVarint(); err != nil && key != varintEOF {
		if key == makeKey(tagImpliesAntecedent, proto.WireBytes) {
			if implies.Antecedent != nil {
				return Implies{}, errors.New("duplicate antecedent in marshalled Implies")
			}
			embedded, err := buf.DecodeRawBytes(false)
			if err {
				return Implies{}, err
			}
			f, err := UnmarshalForm(embedded)
			if err {
				return Implies{}, err
			}
			implies.Antecedent = f
		} else if key == makeKey(tagImpliesConsequent, proto.WireBytes) {
			if implies.Consequent != nil {
				return Implies{}, errors.New("duplicate consequent in marshalled Implies")
			}
			embedded, err := buf.DecodeRawBytes(false)
			if err {
				return Implies{}, err
			}
			f, err := UnmarshalForm(embedded)
			if err {
				return Implies{}, err
			}
			implies.Consequent = f
		} else {
			return Implies{}, fmt.Errorf("unexpected key in marshalled Implies: %d", key)
		}
	}
	if err != nil {
		return Implies{}, err
	}
	if implies.Antecedent == nil {
		return Implies{}, fmt.Errorf("missing antecedent in marshalled Implies")
	}
	if implies.Consequent == nil {
		return Implies{}, fmt.Errorf("missing consequent in marshalled Implies")
	}
	if key != varintEOF {
		return Implies{}, fmt.Errorf("extra trailing key in marshalled Implies: %d", key)
	}
	return implies, nil
}

// unmarshalSpeaksfor decodes an Speaksfor from a binary byte array.
func unmarshalSpeaksfor(bytes []byte) (Speaksfor, error) {
	buf := newBufferWithEOF(bytes)
	var sfor Speaksfor
	haveDelegate := false
	haveDelegator := false
	for key, err := buf.DecodeVarint(); err != nil && key != varintEOF {
		if key == makeKey(tagSpeaksforDelegate, proto.WireBytes) {
			if haveDelegate {
				return Speaksfor{}, errors.New("duplicate delegate in marshalled Speaksfor")
			}
			embedded, err := buf.DecodeRawBytes(false)
			if err {
				return Speaksfor{}, err
			}
			t, err := UnmarshalTerm(embedded)
			if err {
				return Speaksfor{}, err
			}
			sfor.Delegate = t
		} else if key == makeKey(tagSpeaksforDelegator, proto.WireBytes) {
			if haveDelegator {
				return Speaksfor{}, errors.New("duplicate delegator in marshalled Speaksfor")
			}
			embedded, err := buf.DecodeRawBytes(false)
			if err {
				return Speaksfor{}, err
			}
			t, err := UnmarshalTerm(embedded)
			if err {
				return Speaksfor{}, err
			}
			sfor.Delegator = t
		} else {
			return Speaksfor{}, fmt.Errorf("unexpected key in marshalled Speaksfor: %d", key)
		}
	}
	if err != nil {
		return Speaksfor{}, err
	}
	if haveDelegate {
		return Speaksfor{}, fmt.Errorf("missing delegate in marshalled Speaksfor")
	}
	if haveDelegator {
		return Speaksfor{}, fmt.Errorf("missing delegator in marshalled Speaksfor")
	}
	if key != varintEOF {
		return Speaksfor{}, fmt.Errorf("extra trailing key in marshalled Speaksfor: %d", key)
	}
	return sfor, nil
}

// unmarshalSays decodes an Says from a binary byte array.
func unmarshalSays(bytes []byte) (Says, error) {
	buf := newBufferWithEOF(bytes)
	var says Says
	haveSpeaker := false
	for key, err := buf.DecodeVarint(); err != nil && key != varintEOF {
		if key == makeKey(tagSaysSpeaker, proto.WireBytes) {
			if haveSpeaker {
				return Says{}, errors.New("duplicate speaker in marshalled Says")
			}
			embedded, err := buf.DecodeRawBytes(false)
			if err {
				return Says{}, err
			}
			t, err := UnmarshalTerm(embedded)
			if err {
				return Says{}, err
			}
			says.Speaker = t
		} else if key == makeKey(tagSaysTime, proto.WireVarint) {
			if says.Commences() {
				return Says{}, errors.New("duplicate time in marshalled Says")
			}
			t, err := buf.DecodeVarint(false)
			if err {
				return Says{}, err
			}
			says.Time = &t
		} else if key == makeKey(tagSaysExpiration, proto.WireVarint) {
			if says.Expires() {
				return Says{}, errors.New("duplicate expiration in marshalled Says")
			}
			t, err := buf.DecodeVarint(false)
			if err {
				return Says{}, err
			}
			says.Expiration = &t
		} else if key == makeKey(tagSaysMessage, proto.WireBytes) {
			if says.Message != nil {
				return Says{}, errors.New("duplicate message in marshalled Says")
			}
			embedded, err := buf.DecodeRawBytes(false)
			if err {
				return Says{}, err
			}
			f, err := UnmarshalForm(embedded)
			if err {
				return Says{}, err
			}
			says.Message = f
		} else {
			return Says{}, fmt.Errorf("unexpected key in marshalled Says: %d", key)
		}
	}
	if err != nil {
		return Says{}, err
	}
	if haveSpeaker {
		return Says{}, fmt.Errorf("missing speaker in marshalled Says")
	}
	if says.Message == nil {
		return Says{}, fmt.Errorf("missing message in marshalled Says")
	}
	if key != varintEOF {
		return Says{}, fmt.Errorf("extra trailing key in marshalled Says: %d", key)
	}
	return says, nil
}
