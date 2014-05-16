package main

import (
	"cloudproxy/util"
	"fmt"
	"net/rpc"
	"os"
)

func main() {
	fmt.Println("Child started")
	// This program expects to get pipes as file descriptors 3 and 4 (R and W, respectively)
	var clientRWC util.PairReadWriteCloser
	clientRWC.R = os.NewFile(3, "")
	clientRWC.W = os.NewFile(4, "")

	client := rpc.NewClient(clientRWC)
	val := 137
	res := 0

	err := client.Call("AddServer.Get", val, &res)
	if err != nil {
		panic("Couldn't call the server")
	}

	fmt.Println("Got result", res)
}


