package main

import (
	"fmt"
	"net/rpc"
	"os"

	"cloudproxy/tao"
	"cloudproxy/util"
)

func main() {
	fmt.Println("Hosted program started")

	// This program expects to get pipes as file descriptors 3 and 4 (R and W, respectively)
	var clientRWC util.PairReadWriteCloser
	clientRWC.R = os.NewFile(3, "")
	clientRWC.W = os.NewFile(4, "")

	t := &tao.TaoClient {
		Parent: rpc.NewClient(clientRWC),
	}

	b := make([]byte, 10)
	err := t.GetRandomBytes(b)
	if err != nil {
		fmt.Println("Couldn't get random bytes:", err)
		return
	}

	fmt.Println("Got 10 random bytes")
	return
}


