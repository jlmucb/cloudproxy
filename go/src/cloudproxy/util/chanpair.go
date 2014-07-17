package util

type ChanReadWriteCloser struct {
       R <-chan []byte
  W chan []byte
}

func (crw ChanReadWriteCloser) Read(p []byte) (int, error) {
  return copy(p, <-crw.R), nil
}

func (crw ChanReadWriteCloser) Write(p []byte) (int, error) {
  crw.W <- p
       return len(p), nil
}

func (crw ChanReadWriteCloser) Close() error {
  close(crw.W)
  return nil
}

