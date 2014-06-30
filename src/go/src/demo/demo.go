package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"strconv"
	"tao"
)

const (
	server_addr = "localhost:8123"
)

func doServer() {
	fmt.Printf("Entering server mode\n")
	sock, err := net.Listen("tcp", server_addr)
    if err != nil {
		fmt.Printf("Can't listen at %s: %s\n", server_addr, err.Error())
        return
    }
    defer sock.Close()
	fmt.Printf("Listening at %s\n", server_addr)
    for {
        conn, err := sock.Accept()
        if err != nil {
			fmt.Printf("Can't accept connection: %s\n", err.Error())
            return
        }
        // Handle connections in a new goroutine.
        go doRequest(conn)
    }
}

func doRequest(conn net.Conn) {
	defer conn.Close()
	msg, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Printf("Can't read: ", err.Error())
		return
	}
	fmt.Printf("Got message: %s\n", msg)
	fmt.Fprintf(conn, "OK\n")
}

func doClient() {
	fmt.Printf("Entering client mode\n")
	conn, err := net.Dial("tcp", server_addr)
	if err != nil {
		fmt.Printf("Can't connect to %s\n", server_addr)
		return
	}
	defer conn.Close()
	fmt.Fprintf(conn, "Hello\n")
	msg, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Printf("Can't read: ", err.Error())
		return
	}
	fmt.Printf("Got reply: %s\n", msg)
}

func main() {
	fmt.Printf("Go Tao Demo\n")
	host := tao.Host()
	if host == nil {
		fmt.Printf("Can't get host Tao\n")
		return
	}

	var err error

	var name string
	name, err = host.GetTaoName()
	if err != nil {
		fmt.Printf("Can't get my name\n")
		return
	}
	fmt.Printf("My root name is %s\n", name)

	args := make([]string, len(os.Args))
	for index, arg := range os.Args {
		args[index] = strconv.Quote(arg)
	}
	subprin := "Args(" + strings.Join(args, ", ") + ")"
	err = host.ExtendTaoName(subprin)
	if err != nil {
		fmt.Printf("Can't extend my name\n")
		return
	}

	name, err = host.GetTaoName()
	if err != nil {
		fmt.Printf("Can't get my name\n")
		return
	}
	fmt.Printf("My full name is %s\n", name)

	var random []byte
	random, err = host.GetRandomBytes(10)
	if err != nil {
		fmt.Printf("Can't get random bytes\n")
		return
	}
	fmt.Printf("Random bytes  : % x\n", random)

	var secret []byte
	secret, err = host.GetSharedSecret(10, tao.SharedSecretPolicyDefault)
	if err != nil {
		fmt.Printf("Can't get shared secret\n")
		return
	}
	fmt.Printf("Shared secret : % x\n", secret)

	var sealed []byte
	sealed, err = host.Seal(random, tao.SealPolicyDefault)
	if err != nil {
		fmt.Printf("Can't seal bytes\n")
		return
	}
	fmt.Printf("Sealed bytes  : % x\n", sealed)

	var unsealed []byte
	var policy string
	unsealed, policy, err = host.Unseal(sealed)
	if err != nil {
		fmt.Printf("Can't unseal bytes\n")
		return
	}
	if policy != tao.SealPolicyDefault {
		fmt.Printf("Unexpected policy on unseal\n")
		return
	}
	fmt.Printf("Unsealed bytes: % x\n", unsealed)

	if len(os.Args) > 1 && os.Args[1] == "-client" {
		doClient()
	} else if len(os.Args) > 1 && os.Args[1] == "-server" {
		doServer()
	}

}
