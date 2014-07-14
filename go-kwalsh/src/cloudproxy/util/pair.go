package util

import (
	"io"
)

// A PairReadWriteCloser groups an io.Reader, an io.Writer, and up to two
// io.Closer structures into a single structure that implements the
// io.ReadWriteCloser interface. This can be used to turn a pair of
// uni-directional streams into a single bi-directional stream.
type PairReadWriteCloser struct {
	io.Reader
	io.Writer

	// For many stream types, it is an error to close the stream more than once.
	// And sometimes we don't want to close any stream. So we keep zero, one or
	// two io.Closer pointers, one for the reader, one for the writer.
	readCloser, writeCloser io.Closer
}

func (pair PairReadWriteCloser) Close() error {
	var err1, err2 error
	if pair.readCloser != nil {
		err1 = pair.readCloser.Close()
	}
	if pair.writeCloser != nil {
		err2 = pair.writeCloser.Close()
	}
	if err1 != nil {
		return err1
	} else {
		return err2
	}
}

func NewPairReadWriteCloser(r io.Reader, w io.Writer, c1, c2 io.Closer) *PairReadWriteCloser {
	return &PairReadWriteCloser{r, w, c1, c2}
}
