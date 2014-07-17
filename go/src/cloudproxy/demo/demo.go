// File: demo.go
// Author: Kevin Walsh <kwalsh@holycross.edu>
// Description: Demo of hosted program written in go.
//
// Copyright (c) 2013, Google Inc.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"cloudproxy/tao"
)

var server_host = flag.String("host", "localhost", "address for client/server")
var server_port = flag.String("port", "8123", "port for client/server")
var server_addr string // see main()
var local_mode = flag.Bool("local", true, "Run host demo")
var client_mode = flag.Bool("client", true, "Run demo client")
var server_mode = flag.Bool("server", true, "Run demo server")
var ping_count = flag.Int("n", 5, "Number of client/server pings")
var demo_auth = flag.String("auth", "tao", "\"tcp\", \"tls\", or \"tao\"")

// TCP mode client/server

func setupTCPServer() (net.Listener, error) {
	return net.Listen("tcp", server_addr)
}

func setupTCPClient() (net.Conn, error) {
	return net.Dial("tcp", server_addr)
}

// TLS mode client/server

const (
	x509duration = 24 * time.Hour
	x509keySize  = 2048
)

func GenerateX509() (cert tls.Certificate, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, x509keySize)
	if err != nil {
		return
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(x509duration)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Google Tao Demo"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(*server_host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, *server_host)
	}

	// template.IsCA = true
	// template.KeyUsage |= x509.KeyUsageCertSign

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return
	}

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	cert, err = tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		fmt.Printf("can't parse my cert\n")
		return
	}

	return
}

func setupTLSServer() (net.Listener, error) {
	cert, err := GenerateX509()
	if err != nil {
		fmt.Printf("server: can't create key and cert: %s\n", err.Error())
		return nil, err
	}
	return tls.Listen("tcp", server_addr, &tls.Config{
		RootCAs:            x509.NewCertPool(),
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	})
}

func setupTLSClient() (net.Conn, error) {
	cert, err := GenerateX509()
	if err != nil {
		fmt.Printf("client: can't create key and cert: %s\n", err.Error())
		return nil, err
	}
	return tls.Dial("tcp", server_addr, &tls.Config{
		RootCAs:            x509.NewCertPool(),
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	})
}

// client/server driver

func doRequest() bool {
	fmt.Printf("client: connecting to %s using %s authentication.\n", server_addr, *demo_auth)
	var conn net.Conn
	var err error
	switch *demo_auth {
	case "tcp":
		conn, err = setupTCPClient()
	case "tls":
		conn, err = setupTLSClient()
		//case "tao":
		// conn, err = setupTaoClient()
	}
	if err != nil {
		fmt.Printf("client: error connecting to %s: %s\n", server_addr, err.Error())
		return false
	}
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "Hello\n")
	if err != nil {
		fmt.Printf("client: can't write: ", err.Error())
		return false
	}
	msg, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Printf("client can't read: ", err.Error())
		return false
	}
	msg = strings.TrimSpace(msg)
	fmt.Printf("client: got reply: %s\n", msg)
	return true
}

func doClient() {
	ping_good := 0
	ping_fail := 0
	for i := 0; i != *ping_count; i++ { // negative means forever
		if doRequest() {
			ping_good++
		} else {
			ping_fail++
		}
		fmt.Printf("client: made %d connections, finished %d ok, %d bad pings\n",
			i+1, ping_good, ping_fail)
	}
}

func doResponse(conn net.Conn, response_ok chan<- bool) {
	defer conn.Close()

	// todo tao auth
	switch *demo_auth {
	case "tcp", "tls":
	case "tao":
	}

	msg, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Printf("server: can't read: ", err.Error())
		conn.Close()
		response_ok <- false
		return
	}
	msg = strings.TrimSpace(msg)
	fmt.Printf("server: got message: %s\n", msg)
	fmt.Fprintf(conn, "echo(%s)\n", msg)
	conn.Close()
	response_ok <- true
}

func doServer(stop chan bool, ready, done chan<- bool) {
	var sock net.Listener
	var err error
	switch *demo_auth {
	case "tcp":
		sock, err = setupTCPServer()
	case "tls", "tao":
		sock, err = setupTLSServer()
	}
	if err != nil {
		fmt.Printf("server: can't listen at %s: %s\n", server_addr, err.Error())
		ready <- false
		done <- true
		return
	}
	fmt.Printf("server: listening at %s using %s authentication.\n", server_addr, *demo_auth)
	ready <- true

	pings := make(chan bool, 10)
	conn_count := 0

	go func() {
		for conn_count = 0; conn_count != *ping_count; conn_count++ { // negative means forever
			conn, err := sock.Accept()
			if err != nil {
				fmt.Printf("server: can't accept connection: %s\n", err.Error())
				stop <- true
				return
			}
			go doResponse(conn, pings)
		}
		stop <- true
	}()

	ping_good := 0
	ping_fail := 0

loop:
	for {
		select {
		case <-stop:
			break loop
		case ok := <-pings:
			if ok {
				ping_good++
			} else {
				ping_fail++
			}
		}
	}

	sock.Close()
	fmt.Printf("server: handled %d connections, finished %d ok, %d bad pings\n",
		conn_count, ping_good, ping_fail)

	done <- true
}

// Tao Host demo

func hostTaoDemo() error {
	name, err := tao.Host.GetTaoName()
	if err != nil {
		return err
	}
	fmt.Printf("My root name is %s\n", name)

	args := make([]string, len(os.Args))
	for index, arg := range os.Args {
		args[index] = strconv.Quote(arg)
	}
	subprin := "Args(" + strings.Join(args, ", ") + ")"
	err = tao.Host.ExtendTaoName(subprin)
	if err != nil {
		return err
	}

	name, err = tao.Host.GetTaoName()
	if err != nil {
		return err
	}
	fmt.Printf("My full name is %s\n", name)

	random, err := tao.Host.GetRandomBytes(10)
	if err != nil {
		return err
	}
	fmt.Printf("Random bytes  : % x\n", random)

	n, err := tao.Host.Rand().Read(random)
	if err != nil {
		return err
	}
	fmt.Printf("%d more bytes : % x\n", n, random)

	secret, err := tao.Host.GetSharedSecret(10, tao.SharedSecretPolicyDefault)
	if err != nil {
		return err
	}
	fmt.Printf("Shared secret : % x\n", secret)

	sealed, err := tao.Host.Seal(random, tao.SealPolicyDefault)
	if err != nil {
		return err
	}
	fmt.Printf("Sealed bytes  : % x\n", sealed)

	unsealed, policy, err := tao.Host.Unseal(sealed)
	if err != nil {
		return err
	}
	if policy != tao.SealPolicyDefault {
		return errors.New("unexpected policy on unseal")
	}
	fmt.Printf("Unsealed bytes: % x\n", unsealed)

	return nil
}

func main() {
	flag.Parse()
	server_addr = *server_host + ":" + *server_port
	switch *demo_auth {
	case "tcp", "tls", "tao":
	default:
		fmt.Printf("unrecognized authentication mode: %s\n", *demo_auth)
		return
	}

	fmt.Printf("Go Tao Demo\n")

	if tao.Host == nil {
		fmt.Printf("can't continue: No host Tao available")
		return
	}

	if *local_mode {
		err := hostTaoDemo()
		if err != nil {
			fmt.Printf("error: %s\n", err.Error())
			return
		}
	}

	server_stop := make(chan bool, 1)
	server_ready := make(chan bool, 1)
	server_done := make(chan bool, 1)

	if *server_mode {
		go doServer(server_stop, server_ready, server_done)
	} else {
		server_ready <- true
		server_done <- true
	}

	if *client_mode {
		ok := <-server_ready
		if ok {
			doClient()
		}
		server_stop <- true
	}

	<-server_done
	fmt.Printf("Done\n")
}
