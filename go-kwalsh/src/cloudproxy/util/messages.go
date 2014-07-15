package util

import (
	"code.google.com/p/goprotobuf/proto"
	"io"
)

// A MessageReader is a stream from which protobuf messages can be read.
type MessageReader interface {
	ReadMessage(m proto.Message) error
}

// A MessageWriter is a stream to protobuf messages can be written.
type MessageWriter interface {
	WriteMessage(m proto.Message) error
}

// A MessageReadWriteCloser groups the MessageReader, MessageWriter, an
// io.Closer interfaces.

type MessageReadWriteCloser interface {
	MessageReader
	MessageWriter
	io.Closer
}
