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

// This file implements Marshal() and Unmarshal() functions for elements.

import (
	"fmt"
)

const (
	_ = iota

	// Term tags
	tagPrin // string, []byte, SubPrin
	tagStr  // string
	tagInt  // int

	// Form tags
	tagPred      // string, []Term
	tagConst     // bool
	tagNot       // Form
	tagAnd       // []Form
	tagOr        // []Form
	tagImplies   // Form, Form
	tagSpeaksfor // Prin, Prin
	tagSays      // Prin, bool+int, bool+int, Form

	// Other tags
	tagSubPrin // [](string, []Term)
)

// Marshal encodes a Form or Term.
func Marshal(e AuthLogicElement) []byte {
	buf := new(Buffer)
	e.Marshal(buf)
	return buf.Bytes()
}

// Marshal encodes a Prin.
func (t Prin) Marshal(buf *Buffer) {
	buf.EncodeVarint(tagPrin)
	buf.EncodeString(t.Type)
	buf.EncodeString(string(t.Key))
	t.Ext.Marshal(buf)
}

// Marshal encodes a Prin.
func (s SubPrin) Marshal(buf *Buffer) {
	buf.EncodeVarint(tagSubPrin)
	buf.EncodeVarint(int64(len(s)))
	for _, e := range s {
		buf.EncodeString(e.Name)
		buf.EncodeVarint(int64(len(e.Arg)))
		for _, a := range e.Arg {
			a.Marshal(buf)
		}
	}
}

// Marshal encodes a Str.
func (t Str) Marshal(buf *Buffer) {
	buf.EncodeVarint(tagStr)
	buf.EncodeString(string(t))
}

// Marshal encodes an Int.
func (t Int) Marshal(buf *Buffer) {
	buf.EncodeVarint(tagInt)
	buf.EncodeVarint(int64(t))
}

// Marshal encodes a Pred.
func (f Pred) Marshal(buf *Buffer) {
	buf.EncodeVarint(tagPred)
	buf.EncodeString(f.Name)
	buf.EncodeVarint(int64(len(f.Arg)))
	for _, e := range f.Arg {
		e.Marshal(buf)
	}
}

// Marshal encodes a Const.
func (f Const) Marshal(buf *Buffer) {
	buf.EncodeVarint(tagConst)
	buf.EncodeBool(bool(f))
}

// Marshal encodes a Not.
func (f Not) Marshal(buf *Buffer) {
	buf.EncodeVarint(tagNot)
	f.Negand.Marshal(buf)
}

// Marshal encodes an And.
func (f And) Marshal(buf *Buffer) {
	buf.EncodeVarint(tagAnd)
	buf.EncodeVarint(int64(len(f.Conjunct)))
	for _, e := range f.Conjunct {
		e.Marshal(buf)
	}
}

// Marshal encodes an Or.
func (f Or) Marshal(buf *Buffer) {
	buf.EncodeVarint(tagOr)
	buf.EncodeVarint(int64(len(f.Disjunct)))
	for _, e := range f.Disjunct {
		e.Marshal(buf)
	}
}

// Marshal encodes an Implies.
func (f Implies) Marshal(buf *Buffer) {
	buf.EncodeVarint(tagImplies)
	f.Antecedent.Marshal(buf)
	f.Consequent.Marshal(buf)
}

// Marshal encodes a Speaksfor.
func (f Speaksfor) Marshal(buf *Buffer) {
	buf.EncodeVarint(tagSpeaksfor)
	f.Delegate.Marshal(buf)
	f.Delegator.Marshal(buf)
}

// Marshal encodes a Says.
func (f Says) Marshal(buf *Buffer) {
	buf.EncodeVarint(tagSays)
	f.Speaker.Marshal(buf)
	buf.EncodeBool(f.Commences())
	if f.Commences() {
		buf.EncodeVarint(*f.Time)
	}
	buf.EncodeBool(f.Expires())
	if f.Expires() {
		buf.EncodeVarint(*f.Expiration)
	}
	f.Message.Marshal(buf)
}

// decodeStr decodes a Str without the leading tag.
func decodeStr(buf *Buffer) (Str, error) {
	s, err := buf.DecodeString()
	return Str(s), err
}

// decodeInt decodes an Int without the leading tag.
func decodeInt(buf *Buffer) (Int, error) {
	i, err := buf.DecodeVarint()
	return Int(i), err
}

// decodeNameAndArgs decodes a name ad term array without leading tags.
func decodeNameAndArgs(buf *Buffer) (name string, args []Term, err error) {
	name, err = buf.DecodeString()
	if err != nil {
		return
	}
	n, err := buf.DecodeVarint()
	args = make([]Term, n)
	for i := int64(0); i < n; i++ {
		args[i], err = unmarshalTerm(buf)
		if err != nil {
			return
		}
	}
	return
}

// unmarshalPrin decodes a Prin.
func unmarshalPrin(buf *Buffer) (p Prin, err error) {
	tag, err := buf.DecodeVarint()
	if err != nil {
		return
	}
	if tag != tagPrin {
		err = fmt.Errorf("unexpected tag: %d", tag)
		return
	}
	return decodePrin(buf)
}

// decodePrin decodes a Prin without the leading tag.
func decodePrin(buf *Buffer) (p Prin, err error) {
	p.Type, err = buf.DecodeString()
	if err != nil {
		return
	}
	k, err := buf.DecodeString()
	if err != nil {
		return
	}
	p.Key = []byte(k)
	p.Ext, err = decodeSubPrin(buf)
	return
}

// unmarshalSubPrin decodes a SubPrin.
func unmarshalSubPrin(buf *Buffer) (s SubPrin, err error) {
	tag, err := buf.DecodeVarint()
	if err != nil {
		return
	}
	if tag != tagSubPrin {
		err = fmt.Errorf("unexpected tag: %d", tag)
		return
	}
	return decodeSubPrin(buf)
}

// decodeSubPrin decodes a SubPrin without the leading tag.
func decodeSubPrin(buf *Buffer) (s SubPrin, err error) {
	n, err := buf.DecodeVarint()
	if err != nil {
		return
	}
	for i := int64(0); i < n; i++ {
		name, args, err := decodeNameAndArgs(buf)
		if err != nil {
			return s, err
		}
		s= append(s, PrinExt{name, args})
	}
	return
}

// unmarshalTerm decodes a Term.
func unmarshalTerm(buf *Buffer) (t Term, err error) {
	tag, err := buf.DecodeVarint()
	if err != nil {
		return nil, err
	}
	switch tag {
	case tagStr:
		return decodeStr(buf)
	case tagInt:
		return decodeInt(buf)
	case tagPrin:
		return decodePrin(buf)
	default:
		return nil, fmt.Errorf("unexpected tag: %d", tag)
	}
}

// UnmarshalPrin decodes a Prin.
func UnmarshalPrin(bytes []byte) (p Prin, err error) {
	t, err := UnmarshalTerm(bytes)
	if err != nil {
		return
	}
	p, ok := t.(Prin)
	if !ok {
		err = fmt.Errorf("expected Prin, found %T", t)
	}
	return
}

// UnmarshalTerm decodes a Term.
func UnmarshalTerm(bytes []byte) (Term, error) {
	buf := &Buffer{bytes}
	t, err := unmarshalTerm(buf)
	if err != nil {
		return nil, err
	}
	if len(buf.Bytes()) != 0 {
		return nil, fmt.Errorf("unexpected trailing bytes")
	}
	return t, nil
}

// UnmarshalSubPrin decodes a SubPrin.
func UnmarshalSubPrin(bytes []byte) (SubPrin, error) {
	buf := &Buffer{bytes}
	t, err := unmarshalSubPrin(buf)
	if err != nil {
		return nil, err
	}
	if len(buf.Bytes()) != 0 {
		return nil, fmt.Errorf("unexpected trailing bytes")
	}
	return t, nil
}

// UnmarshalForm decodes a Form.
func UnmarshalForm(bytes []byte) (Form, error) {
	buf := &Buffer{bytes}
	f, err := unmarshalForm(buf)
	if err != nil {
		return nil, err
	}
	if len(buf.Bytes()) != 0 {
		return nil, fmt.Errorf("unexpected trailing bytes")
	}
	return f, nil
}

// unmarshalForm decodes a Form.
func unmarshalForm(buf *Buffer) (Form, error) {
	tag, err := buf.DecodeVarint()
	if err != nil {
		return nil, err
	}
	switch tag {
	case tagPred:
		return decodePred(buf)
	case tagConst:
		return decodeConst(buf)
	case tagNot:
		return decodeNot(buf)
	case tagAnd:
		return decodeAnd(buf)
	case tagOr:
		return decodeOr(buf)
	case tagImplies:
		return decodeImplies(buf)
	case tagSpeaksfor:
		return decodeSpeaksfor(buf)
	case tagSays:
		return decodeSays(buf)
	default:
		return nil, fmt.Errorf("unexpected tag: %d", tag)
	}
}

// decodePred decodes a Pred without the leading tag.
func decodePred(buf *Buffer) (Pred, error) {
	name, args, err := decodeNameAndArgs(buf)
	return Pred{name, args}, err
}

// decodeConst decodes a Const without the leading tag.
func decodeConst(buf *Buffer) (Const, error) {
	b, err := buf.DecodeBool()
	return Const(b), err
}

// decodeNot decodes a Not without the leading tag.
func decodeNot(buf *Buffer) (Not, error) {
	f, err := unmarshalForm(buf)
	return Not{f}, err
}

// decodeAnd decodes an And without the leading tag.
func decodeAnd(buf *Buffer) (and And, err error) {
	n, err := buf.DecodeVarint()
	if err != nil {
		return
	}
	for i := int64(0); i < n; i++ {
		f, err := unmarshalForm(buf)
		if err != nil {
			return and, err
		}
		and.Conjunct = append(and.Conjunct, f)
	}
	return
}

// decodeOr decodes an Or without the leading tag.
func decodeOr(buf *Buffer) (or Or, err error) {
	n, err := buf.DecodeVarint()
	if err != nil {
		return
	}
	for i := int64(0); i < n; i++ {
		f, err := unmarshalForm(buf)
		if err != nil {
			return or, err
		}
		or.Disjunct = append(or.Disjunct, f)
	}
	return
}

// decodeImplies decodes an Implies without the leading tag.
func decodeImplies(buf *Buffer) (implies Implies, err error) {
	implies.Antecedent, err = unmarshalForm(buf)
	if err != nil {
		return
	}
	implies.Consequent, err = unmarshalForm(buf)
	return
}

// decodeSpeaksfor decodes an Speaksfor without the leading tag.
func decodeSpeaksfor(buf *Buffer) (sfor Speaksfor, err error) {
	sfor.Delegate, err = unmarshalPrin(buf)
	if err != nil {
		return
	}
	sfor.Delegator, err = unmarshalPrin(buf)
	return
}

// decodeSays decodes an Says without the leading tag.
func decodeSays(buf *Buffer) (says Says, err error) {
	says.Speaker, err = unmarshalPrin(buf)
	if err != nil {
		return
	}
	commences, err := buf.DecodeBool()
	if err != nil {
		return
	}
	if commences {
		t, err := buf.DecodeVarint()
		if err != nil {
			return says, err
		}
		says.Time = &t
	}
	expires, err := buf.DecodeBool()
	if err != nil {
		return
	}
	if expires {
		t, err := buf.DecodeVarint()
		if err != nil {
			return says, err
		}
		says.Expiration = &t
	}
	says.Message, err = unmarshalForm(buf)
	return
}
