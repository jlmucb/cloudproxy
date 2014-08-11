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

// Buffer holds partially encoded or decode auth elemnts.
// Note: We could do capacity-doubling, etc., but we favor simplicity for now.
type Buffer struct {
	buf []byte
}

// Bytes returns the unconsumed portion of the buffer.
func (b *Buffer) Bytes() []byte {
	return b.buf
}

// EncodeVarint encodes an int as a (non zig-zag) varint, growing the buffer.
func (b *Buffer) EncodeVarint(i int64) {
	buf := make([]byte, 10) // int64 as varint is max 10 bytes
	i := binary.PutUvarint(buf, uint64(i))
	b.buf = append(b.buf, buf[0:i]...)
}

// DecodeVarint decodes an int, shrinking the buffer.
func (b *Buffer) DecodeVarint() int64, error {
	i, n := binary.Uvarint(b.buf)
	if n == 0 {
		return 0, io.unexpectedEOF
	} else if n < 0 {
		return 0, errors.New("varint overflow")
	}
	b.buf = b.buf[n:]
	return int64(i), nil
}

// EncodeBool converts b to an int then calls EncodeVarint.
func (b *Buffer) EncodeBool(b bool) {
	if b {
		b.EncodeVarint(1)
	} else {
		b.EncodeVarint(0)
	}
}

// DecodeBool calls DecodeVarint then converts the result to a bool.
func (b *Buffer) DecodeBool() bool, error {
	i, err := b.DecodeVarint()
	return (i == 1), err
}

// EncodeString encodes a string as a length and byte array, growing the buffer.
func (b *Buffer) EncodeString(s string) {
	bytes := []byte(s)
	b.EncodeVarint(len(bytes))
	b.buf = append(b.buf, bytes...)
}

// DecodeString decodes a string, shrinking the buffer.
func (b *Buffer) DecodeString() string, error {
	n, err := b.DecodeVarint()
	if err != nil {
		return "", err
	}
	if n < 0 || n > len(b.buf) {
		return "", fmt.Errorf("invalid length: %d", n)
	}
	s := string(b.buf[:n])
	b.buf = b.buf[n:]
	return s, nil
}

