package main

import (
	"cloudproxy/util"
	"fmt"
	"net/rpc"
	"os"
	"os/exec"
)

type AddServer struct {
	Val int
}

func (s *AddServer) Get(addend int, result *int) error {
	*result = addend + s.Val
	return nil
}

func main() {
	// Set up the two-way communication channels
	var serverRWC util.PairReadWriteCloser
	var err error
	var clientRead, clientWrite *os.File
	serverRWC.R, clientWrite, err = os.Pipe()
	if err != nil {
		panic("Couldn't create a pipe")
	}

	clientRead, serverRWC.W, err = os.Pipe()
	if err != nil {
		panic("Couldn't create the second pipe")
	}

	server := rpc.NewServer()

	as := new(AddServer)
	as.Val = 137
	err = server.Register(as)
	if err != nil {
		panic("Couldn't register the AddServer as a service")
	}

	// Start the child program.
	var c exec.Cmd
	c.Path = "./child"
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.ExtraFiles = []*os.File{clientRead, clientWrite}

	// Note that in practice, you'd want to set the Credential here, at least.
	fmt.Println("About to start the child")
	err = c.Start()
	if err != nil {
		panic("Couldn't start the command")
	}
	fmt.Println("Started the child. About to serve the connection")
	server.ServeConn(serverRWC)
}
