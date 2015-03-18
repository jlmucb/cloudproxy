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

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Buffer holds partially encoded or decode auth elemnts.
// Note: We could do capacity-doubling, etc., but we favor simplicity for now.
type Buffer struct {
	buf []byte
}

// Bytes returns the unconsumed portion of the buffer.
func (buf *Buffer) Bytes() []byte {
	return buf.buf
}

// EncodeVarint encodes an int as a (non zig-zag) varint, growing the buffer.
func (buf *Buffer) EncodeVarint(i int64) {
	b := make([]byte, 10) // int64 as varint is max 10 bytes
	n := binary.PutUvarint(b, uint64(i))
	buf.buf = append(buf.buf, b[0:n]...)
}

// DecodeVarint decodes an int, shrinking the buffer.
func (buf *Buffer) DecodeVarint() (int64, error) {
	i, n := binary.Uvarint(buf.buf)
	if n == 0 {
		return 0, io.ErrUnexpectedEOF
	} else if n < 0 {
		return 0, errors.New("varint overflow")
	}
	buf.buf = buf.buf[n:]
	return int64(i), nil
}

// EncodeBool converts b to an int then calls EncodeVarint.
func (buf *Buffer) EncodeBool(b bool) {
	if b {
		buf.EncodeVarint(1)
	} else {
		buf.EncodeVarint(0)
	}
}

// DecodeBool calls DecodeVarint then converts the result to a bool.
func (buf *Buffer) DecodeBool() (bool, error) {
	i, err := buf.DecodeVarint()
	return (i == 1), err
}

// EncodeString encodes a string as a length and byte array, growing the buffer.
func (buf *Buffer) EncodeString(s string) {
	bytes := []byte(s)
	buf.EncodeVarint(int64(len(bytes)))
	buf.buf = append(buf.buf, bytes...)
}

// DecodeString decodes a string, shrinking the buffer.
func (buf *Buffer) DecodeString() (string, error) {
	n, err := buf.DecodeVarint()
	if err != nil {
		return "", err
	}
	if n < int64(0) || n > int64(len(buf.buf)) {
		return "", fmt.Errorf("invalid length: %d", n)
	}
	s := string(buf.buf[:n])
	buf.buf = buf.buf[n:]
	return s, nil
}
