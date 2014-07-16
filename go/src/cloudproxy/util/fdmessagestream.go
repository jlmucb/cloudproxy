package util

import (
	"errors"
	"fmt"
	"os"
)

// DeserializeFDMessageStream takes a string description of the form
// "tao::FDMessageStream(X, Y)" and returns a MessageStream that uses file
// descriptor X as the reader and file descriptor Y as the writer.
func DeserializeFDMessageStream(s string) (*MessageStream, error) {
	var readfd, writefd uintptr
	_, err := fmt.Sscanf(s, "tao::FDMessageChannel(%d, %d)", &readfd, &writefd)
	if err != nil {
		return nil, errors.New("Unrecognized channel spec: " + s)
	}
	if readfd == writefd {
		rw := os.NewFile(readfd, "read/write pipe")
		return NewMessageStream(rw), nil
	} else {
		r := os.NewFile(readfd, "read pipe")
		w := os.NewFile(writefd, "write pipe")
		rw := NewPairReadWriteCloser(r, w)
		return NewMessageStream(rw), nil
	}
}

