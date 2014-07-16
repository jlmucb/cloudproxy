package util

import (
	"code.google.com/p/goprotobuf/proto"
)

// A MessageReader is a stream from which protobuf messages can be read.
type MessageReader interface {
	ReadMessage(m proto.Message) error
}

// A MessageWriter is a stream to which protobuf messages can be written.
type MessageWriter interface {
	WriteMessage(m proto.Message) error
}

// A StringReader is a stream from which strings can be read.
type StringReader interface {
	ReadString() (string, error)
}

// A StringWriter is a stream to which strings can be written.
type StringWriter interface {
	WriteString(s string) (n int, err error)
}
