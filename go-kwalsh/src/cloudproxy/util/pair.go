package util

import (
	"io"
	"io/ioutil"
)

// A PairReadWriteCloser groups an io.ReadCloser and an io.WritCloser into a
// single structure that implements the io.ReadWriteCloser interface. This can
// be used to turn a pair of uni-directional streams into a single
// bi-directional stream.
type PairReadWriteCloser struct {
	io.ReadCloser
	io.WriteCloser
}

func (pair PairReadWriteCloser) Close() error {
	err1 := pair.ReadCloser.Close()
	err2 := pair.WriteCloser.Close()
	if err1 != nil {
		return err1
	} else {
		return err2
	}
}

func NewPairReadWriteCloser(r io.ReadCloser, w io.WriteCloser) *PairReadWriteCloser {
	if rw, _ := w.(io.ReadCloser); r == rw {
		return &PairReadWriteCloser{ioutil.NopCloser(r), w}
	} else {
		return &PairReadWriteCloser{r, w}
	}
}
