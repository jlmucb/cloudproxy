//  File: rpc_channel.go
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: An interface for a Message channel.
//
//  Copyright (c) 2013, Google Inc.  All rights reserved.
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

package tao

import (
	"code.google.com/p/goprotobuf/proto"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
)

const (
	DefaultMaxMessageSize = 20 * 1024 * 1024
)

type MessageChannel struct {
	maxMessageSize uint
	pipe io.ReadWriteCloser
}

// Close closes a channel. It is safe to call this multiple times.
func (mc *MessageChannel) Close() error {
	if mc.pipe != nil {
		mc.pipe.Close()
		mc.pipe = nil
	}
	return nil
}

// IsClosed checks if a channel is closed.
func (mc *MessageChannel) IsClosed() bool {
	return mc.pipe == nil
}

// MaxMessageSize gets the maximum message reception size.
func (mc *MessageChannel) MaxMessageSize() uint {
	return mc.maxMessageSize
}

// SetMaxMessageSize sets the maximum message reception size.
func (mc *MessageChannel) SetMaxMessageSize(size uint) {
	mc.maxMessageSize = size
}

// SendData sends raw data to the channel.
// Failure will close the channel.
func (mc *MessageChannel) SendData(bytes []byte) error {
	_, err := mc.pipe.Write(bytes)
	if err != nil {
		mc.Close()
	}
	return err
}

// ReceiveData receives raw data from the channel.
// No maximum message size applies, the caller is expected to supply a
// reasonable size buffer, which will be filled entirely.
// Failure or eof will close the channel.
func (mc *MessageChannel) ReceiveData(bytes []byte) error {
	_, err := io.ReadFull(mc.pipe, bytes)
	if err != nil {
		mc.Close()
	}
	return err
}

// SendString sends a raw string to the channel.
// Failure will close the channel.
func (mc *MessageChannel) SendString(s string) error {
	n := len(s)
	if n > math.MaxUint32 {
		return errors.New("String too large")
	}
	bytes := make([]byte, 4+n)
	binary.BigEndian.PutUint32(bytes[0:4], uint32(n))
	copy(bytes[4:], s)
	return mc.SendData(bytes)
}

// ReceiveString receives a string over the channel.
// Failure or eof will close the channel.
func (mc *MessageChannel) ReceiveString() (string, error) {
	var sizebytes [4]byte
	_, err := io.ReadFull(mc.pipe, sizebytes[:])
	if err != nil {
		return "", err
	}
	n := binary.BigEndian.Uint32(sizebytes[:])
	strbytes := make([]byte, n)
	_, err = io.ReadFull(mc.pipe, strbytes)
	if err != nil {
		return "", err
	}
	return string(strbytes), nil
}

// SendMessage sends a Message to the channel.
// Failure will close the channel.
func (mc *MessageChannel) SendMessage(m proto.Message) error {
	bytes, err := proto.Marshal(m)
	if err != nil {
		mc.Close()
		return err
	}
	return mc.SendString(string(bytes))
}

// ReceiveMessage receives a Message (of a particular type) over the
// channel. Failure or eof will close the channel.
func (mc *MessageChannel) ReceiveMessage(m proto.Message) error {
	s, err := mc.ReceiveString()
	if err != nil {
		return err
	}
	err = proto.Unmarshal([]byte(s), m)
	if err != nil {
		mc.Close()
		return err
	}
	return nil
}

type readerWriterPair struct {
	io.Reader
	io.Writer
	readCloser, writeCloser io.Closer
}

func (pipe *readerWriterPair) Close() error {
	var err1, err2 error
	if pipe.readCloser != nil {
		err1 = pipe.readCloser.Close()
	}
	if pipe.writeCloser != nil {
		err2 = pipe.writeCloser.Close()
	}
	if err1 != nil {
		return err1
	} else {
		return err2
	}
}

func DeserializeMessageChannel(s string) *MessageChannel {
	var readfd, writefd uintptr
	_, err := fmt.Sscanf(s, "tao::FDMessageChannel(%d, %d)", &readfd, &writefd)
	if err != nil {
		fmt.Printf("bad scanf: %s\n", s)
		return nil
	}
	reader := os.NewFile(readfd, "read pipe")
	writer := os.NewFile(writefd, "write pipe")
	var pipe io.ReadWriteCloser
	if readfd == writefd {
		pipe = &readerWriterPair{reader, writer, reader, nil}
	} else {
		pipe = &readerWriterPair{reader, writer, reader, writer}
	}
	return &MessageChannel{DefaultMaxMessageSize, pipe}
}
