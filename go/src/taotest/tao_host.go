package main

import (
	"fmt"
	"net/rpc"
	"os"
	"os/exec"

	"cloudproxy/tao"
	"cloudproxy/util"
)

func main() {
	// Set up the two-way communication channels
	var serverRWC util.PairReadWriteCloser
	var err error
	var clientRead, clientWrite *os.File
	serverRWC.R, clientWrite, err = os.Pipe()
	if err != nil {
		panic(err)
	}

	clientRead, serverRWC.W, err = os.Pipe()
	if err != nil {
		panic(err)
	}

	server := rpc.NewServer()
	s := new(tao.SoftTao)
	if err = s.Init("test", "crypter", "signer"); err != nil {
		panic(err)
	}

	fmt.Println("Initialized the keys")

	ts := &tao.TaoServer{
		T: s,
	}

	err = server.Register(ts)
	if err != nil {
		panic(err)
	}

	// Start the child program.
	var c exec.Cmd
	c.Path = "./hosted_program"
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.ExtraFiles = []*os.File{clientRead, clientWrite}

	// Note that in practice, you'd want to set the Credential here, at least.
	fmt.Println("About to start the hosted program")
	err = c.Start()
	if err != nil {
		panic(err)
	}
	fmt.Println("Started the child. About to serve the connection")
	server.ServeConn(serverRWC)
}
