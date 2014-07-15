package util

import (
	"fmt"
	"os"
)

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
	if readfd == writefd {
		rw := os.NewFile(readfd, "read/write pipe")
		return NewMessageStream(rw)
	} else {
		r := os.NewFile(readfd, "read pipe")
		w := os.NewFile(writefd, "write pipe")
		rw := NewPairReadWriteCloser(r, w)
		return NewMessageStream(rw)
	}
}

