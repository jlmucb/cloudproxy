package util

import (
	"code.google.com/p/goprotobuf/proto"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
)
// A MessageStream is a bi-direction stream that can read or write three kinds
// of messages: byte slices, strings, and protobuf messages. It is up to the
// caller to ensure that each type of write is paired with the appropriate type
// of read. In addition, a MessageStream can enforce an upper-limit on the size
// of received messages.
type MessageStream struct {
	maxMessageSize uint
	pipe io.ReadWriteCloser
}

const (
	DefaultMaxMessageSize = 20 * 1024 * 1024
)

// type MessageReader interface {
// 	func MaxMessageSize() uint
// 	func SetMaxMessageSize(size uint)
// 	func ReceiveData(bytes []byte) error
// 	func ReceiveString() (string, error)
// 	func ReceiveMessage(m proto.Message) error
// }
// type MessageWriter interface {
// 	func SendData(bytes []byte) error
// 	func SendString(s string) error
// 	func SendMessage(m proto.Message) error
// }
// type MessageReadWritCloser interface {
// 	io.Closer
// 	MessageReader
// 	MessageWriter
// }


// Close closes a MessageStream. It is safe to call this multiple times.
func (mc *MessageStream) Close() error {
	if mc.pipe != nil {
		mc.pipe.Close()
		mc.pipe = nil
	}
	return nil
}

// MaxMessageSize gets the maximum message reception size.
func (mc *MessageStream) MaxMessageSize() uint {
	return mc.maxMessageSize
}

// SetMaxMessageSize sets the maximum message reception size.
func (mc *MessageStream) SetMaxMessageSize(size uint) {
	mc.maxMessageSize = size
}

// SendData sends raw data to the channel.
// Failure will close the channel.
func (mc *MessageStream) SendData(bytes []byte) error {
	if mc.pipe == nil {
		return io.EOF
	}
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
func (mc *MessageStream) ReceiveData(bytes []byte) error {
	if mc.pipe == nil {
		return io.EOF
	}
	_, err := io.ReadFull(mc.pipe, bytes)
	if err != nil {
		mc.Close()
	}
	return err
}

// SendString sends a raw string to the channel.
// Failure will close the channel.
func (mc *MessageStream) SendString(s string) error {
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
func (mc *MessageStream) ReceiveString() (string, error) {
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

// SendMessage sends a Message to the channel.
// Failure will close the channel.
func (mc *MessageStream) SendMessage(m proto.Message) error {
	bytes, err := proto.Marshal(m)
	if err != nil {
		mc.Close()
		return err
	}
	return mc.SendString(string(bytes))
}

// ReceiveMessage receives a Message (of a particular type) over the
// channel. Failure or eof will close the channel.
func (mc *MessageStream) ReceiveMessage(m proto.Message) error {
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

// DeserializeMessageStream takes a string description of the form
// "tao::FDMessageStream(X, Y)" and returns a MessageStream that uses file
// descriptor X as the underlying reader and file descriptor write as the
// underlying writer. 
func DeserializeMessageStream(s string) *MessageStream {
	var readfd, writefd uintptr
	_, err := fmt.Sscanf(s, "tao::FDMessageStream(%d, %d)", &readfd, &writefd)
	if err != nil {
		fmt.Printf("bad scanf: %s\n", s)
		return nil
	}
	reader := os.NewFile(readfd, "read pipe")
	writer := os.NewFile(writefd, "write pipe")
	var pipe io.ReadWriteCloser
	if readfd == writefd {
		pipe = NewPairReadWriteCloser(reader, writer, nil, writer)
	} else {
		pipe = NewPairReadWriteCloser(reader, writer, reader, writer)
	}
	return &MessageStream{DefaultMaxMessageSize, pipe}
}

// NewMessageStream creates a new MessageStream for the given pipe.
func NewMessageStream(pipe io.ReadWriteCloser) *MessageStream {
	return &MessageStream{DefaultMaxMessageSize, pipe}
}

