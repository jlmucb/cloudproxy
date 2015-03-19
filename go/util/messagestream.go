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

package util

import (
	"encoding/binary"
	"errors"
	"io"
	"math"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
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

// DefaultMaxMessageSize gives the default max for messages sent on a
// MessageStream.
const DefaultMaxMessageSize = 20 * 1024 * 1024

// ErrMessageTooLarge is the error message returned when a message larger than
// DefaultMaxMessageSize is sent on a MessageStream.
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
		return n, Logged(err)
	}
	m, err := ms.Write([]byte(s))
	return n + m, Logged(err)
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
		glog.Errorf("String on wire is too large: %d bytes\n", n)
		return "", Logged(ErrMessageTooLarge)
	}
	strbytes := make([]byte, int(n))
	_, err = io.ReadFull(ms, strbytes)
	if err != nil {
		return "", Logged(err)
	}
	return string(strbytes), nil
}

// WriteMessage writes 32-bit length followed by a protobuf message. If m is
// nil, a blank message is written instead.
func (ms *MessageStream) WriteMessage(m proto.Message) (int, error) {
	if m == nil {
		return ms.WriteString("")
	}
	bytes, err := proto.Marshal(m)
	if err != nil {
		return 0, Logged(err)
	}
	return ms.WriteString(string(bytes))
}

// ReadMessage reads a 32-bit length followed by a protobuf message. If m is
// nil, the incoming message is discarded.
func (ms *MessageStream) ReadMessage(m proto.Message) error {
	s, err := ms.ReadString()
	if err != nil {
		return err
	}
	if m != nil {
		err = proto.Unmarshal([]byte(s), m)
		if err != nil {
			return Logged(err)
		}
	}
	return nil
}

// NewMessageStream creates a MessageStream for the given pipe with a reception
// limit of DefaultMaxMessageSize.
func NewMessageStream(pipe io.ReadWriteCloser) *MessageStream {
	return &MessageStream{DefaultMaxMessageSize, pipe}
}
