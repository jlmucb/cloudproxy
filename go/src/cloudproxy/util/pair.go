package util

import (
	"io"
)

type PairReadWriteCloser struct {
	R io.ReadCloser
	W io.WriteCloser
}

func (prw PairReadWriteCloser) Read(p []byte) (n int, err error) {
	n, err = prw.R.Read(p)
	return
}

func (prw PairReadWriteCloser) Write(p []byte) (n int, err error) {
	n, err = prw.W.Write(p)
	return
}

func (prw PairReadWriteCloser) Close() (err error) {
	err = prw.R.Close()
	if err != nil {
		return
	}

	err = prw.W.Close()
	return
}
