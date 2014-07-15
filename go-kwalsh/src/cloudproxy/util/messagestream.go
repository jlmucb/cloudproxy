package util

import (
	"code.google.com/p/goprotobuf/proto"
	"encoding/binary"
	"errors"
	"io"
	"math"
)

// A MessageStream is a bi-direction stream of protobuf messages. A
// MessageStream can also enforce an upper-limit on the size of received
// messages.
type MessageStream struct {
	maxMessageSize uint
	pipe io.ReadWriteCloser
}

const (
	DefaultMaxMessageSize = 20 * 1024 * 1024
)

// Close closes a MessageStream. It is safe to call this multiple times.
func (mc *MessageStream) Close() error {
	if mc.pipe != nil {
		mc.pipe.Close()
		mc.pipe = nil
	}
	return nil
}

// MaxMessageSize gets the maximum message reception size. Zero means unlimited.
func (mc *MessageStream) MaxMessageSize() uint {
	return mc.maxMessageSize
}

// SetMaxMessageSize sets the maximum message reception size. Zero means
// unlimited.
func (mc *MessageStream) SetMaxMessageSize(size uint) {
	mc.maxMessageSize = size
}

// WriteData sends raw data to the channel.
// Failure will close the channel.
func (mc *MessageStream) WriteData(bytes []byte) error {
	if mc.pipe == nil {
		return io.EOF
	}
	_, err := mc.pipe.Write(bytes)
	if err != nil {
		mc.Close()
	}
	return err
}

// ReadData receives raw data from the channel.
// No maximum message size applies, the caller is expected to supply a
// reasonable size buffer, which will be filled entirely.
// Failure or eof will close the channel.
func (mc *MessageStream) ReadData(bytes []byte) error {
	if mc.pipe == nil {
		return io.EOF
	}
	_, err := io.ReadFull(mc.pipe, bytes)
	if err != nil {
		mc.Close()
	}
	return err
}

// WriteString sends a raw string to the channel.
// Failure will close the channel.
func (mc *MessageStream) WriteString(s string) error {
	n := len(s)
	if n > math.MaxUint32 {
		return errors.New("String too large")
	}
	bytes := make([]byte, 4+n)
	binary.BigEndian.PutUint32(bytes[0:4], uint32(n))
	copy(bytes[4:], s)
	return mc.WriteData(bytes)
}

// ReadString receives a string over the channel.
// Failure or eof will close the channel.
func (mc *MessageStream) ReadString() (string, error) {
	if mc.pipe == nil {
		return "", io.EOF
	}
	var sizebytes [4]byte
	_, err := io.ReadFull(mc.pipe, sizebytes[:])
	if err != nil {
		mc.Close()
		return "", err
	}
	n := binary.BigEndian.Uint32(sizebytes[:])
	if (mc.maxMessageSize > 0 && uint(n) > mc.maxMessageSize) {
		mc.Close()
		return "", errors.New("String to large")
	}
	strbytes := make([]byte, n)
	_, err = io.ReadFull(mc.pipe, strbytes)
	if err != nil {
		mc.Close()
		return "", err
	}
	return string(strbytes), nil
}

// WriteMessage sends a Message to the channel.
// Failure will close the channel.
func (mc *MessageStream) WriteMessage(m proto.Message) error {
	bytes, err := proto.Marshal(m)
	if err != nil {
		mc.Close()
		return err
	}
	return mc.WriteString(string(bytes))
}

// ReadMessage receives a Message (of a particular type) over the
// channel. Failure or eof will close the channel.
func (mc *MessageStream) ReadMessage(m proto.Message) error {
	s, err := mc.ReadString()
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

// NewMessageStream creates a new MessageStream for the given pipe.
func NewMessageStream(pipe io.ReadWriteCloser) *MessageStream {
	return &MessageStream{DefaultMaxMessageSize, pipe}
}

