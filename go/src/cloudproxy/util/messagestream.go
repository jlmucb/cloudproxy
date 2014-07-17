// File: messagestream.go
// Author: Kevin Walsh <kwalsh@holycross.edu>
// Description: Streams for delineated strings and protobuf messages.
//
// Copyright (c) 2013, Google Inc.  All rights reserved.
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

package util

import (
	"encoding/binary"
	"errors"
	"io"
	"math"

	"code.google.com/p/goprotobuf/proto"
)

// A MessageStream is an io.ReadWriteCloser that can also read and write strings
// and protobuf messages. Boundaries are preserved for strings and protobuf
// messages using a 32-bit (network byte order) length prefix before the
// contents of the string or marshalled protobuf message. MessageStream can also
// enforce an upper-limit on the size of received messages.
type MessageStream struct {
	MaxMessageSize int // Negative means unlimited
	io.ReadWriteCloser
}

const DefaultMaxMessageSize = 20 * 1024 * 1024

var ErrMessageTooLarge = errors.New("messagestream: message is too large")

// WriteString writes a 32-bit length followed by the string.
func (ms *MessageStream) WriteString(s string) (int, error) {
	n := len(s)
	if n > math.MaxUint32 {
		return 0, ErrMessageTooLarge
	}
	var sizebytes [4]byte
	binary.BigEndian.PutUint32(sizebytes[:], uint32(n))
	n, err := ms.Write(sizebytes[:])
	if err != nil {
		return n, err
	}
	m, err := ms.Write([]byte(s))
	return n + m, err
}

// ReadString reads a 32-bit length followed by a string.
func (ms *MessageStream) ReadString() (string, error) {
	var sizebytes [4]byte
	_, err := io.ReadFull(ms, sizebytes[:])
	if err != nil {
		return "", err
	}
	n := binary.BigEndian.Uint32(sizebytes[:])
	max := ms.MaxMessageSize
	// We also check for int(n) to overflow so allocation below doesn't fail.
	if int(n) < 0 || (max > 0 && int(n) > max) {
		return "", ErrMessageTooLarge
	}
	strbytes := make([]byte, int(n))
	_, err = io.ReadFull(ms, strbytes)
	if err != nil {
		return "", err
	}
	return string(strbytes), nil
}

// WriteMessage writes 32-bit length followed by a protobuf message.
func (ms *MessageStream) WriteMessage(m proto.Message) (int, error) {
	bytes, err := proto.Marshal(m)
	if err != nil {
		return 0, err
	}
	return ms.WriteString(string(bytes))
}

// ReadMessage reads a 32-bit length followed by a protobuf message.
func (ms *MessageStream) ReadMessage(m proto.Message) error {
	s, err := ms.ReadString()
	if err != nil {
		return err
	}
	err = proto.Unmarshal([]byte(s), m)
	if err != nil {
		return err
	}
	return nil
}

// NewMessageStream creates a MessageStream for the given pipe with a reception
// limit of DefaultMaxMessageSize.
func NewMessageStream(pipe io.ReadWriteCloser) *MessageStream {
	return &MessageStream{DefaultMaxMessageSize, pipe}
}
