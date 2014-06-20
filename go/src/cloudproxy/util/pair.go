package util

import (
	"io"
)

type PairReadWriteCloser struct {
	R io.ReadCloser
	W io.WriteCloser
}

func (prw PairReadWriteCloser) Read(p []byte) (int, error) {
	return prw.R.Read(p)
}

func (prw PairReadWriteCloser) Write(p []byte) (int, error) {
	return prw.W.Write(p)
}

func (prw PairReadWriteCloser) Close() error {
	err := prw.R.Close()
	if err != nil {
		return err
	}

	return prw.W.Close()
}
