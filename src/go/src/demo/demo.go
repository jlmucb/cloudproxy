package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"
	"strconv"
	"tao"
)

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)


const (
	server_host = "localhost"
	server_port = "8123"
	server_addr = server_host + ":" + server_port
)

func doTCPServer() {
	fmt.Printf("Entering TCP server mode\n")
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
        go simpleResponse(conn, "OK\n")
    }
}

func simpleResponse(conn net.Conn, response string) {
	defer conn.Close()
	msg, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Printf("Can't read: ", err.Error())
		return
	}
	fmt.Printf("Got message: %s\n", msg)
	fmt.Fprintf(conn, response)
}

func doTCPClient() {
	fmt.Printf("Entering TCP client mode\n")
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

/// Generate self-signed x509 cert.

const (
	x509duration = 24*time.Hour
	x509keySize = 2048
)

func GenerateX509() (certPemBytes []byte, keyPemBytes []byte, err error) {

	priv, err := rsa.GenerateKey(rand.Reader, x509keySize)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(x509duration)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Google Tao Demo"},
		},
		NotBefore: notBefore,
		NotAfter: notAfter,
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(server_host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, server_host)
	}

	// template.IsCA = true
	// template.KeyUsage |= x509.KeyUsageCertSign

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certPemBytes = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPemBytes = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return certPemBytes, keyPemBytes, nil
}

func doTLSServer() {
	fmt.Printf("Entering TLS server mode\n")

	certPem, keyPem, err := GenerateX509()
	if err != nil {
		fmt.Printf("Can't create key: %s\n", err.Error())
        return
    }

	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		fmt.Printf("Can't parse my cert\n")
		return
	}

	sock, err := tls.Listen("tcp", server_addr, &tls.Config{
		RootCAs: x509.NewCertPool(),
		Certificates: []tls.Certificate{ cert },
		InsecureSkipVerify: true,
	})
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
        go simpleResponse(conn, "OK Secret\n")
    }
}

func doTLSClient() {
	fmt.Printf("Entering TLS client mode\n")

	certPem, keyPem, err := GenerateX509()
	if err != nil {
		fmt.Printf("Can't create key: %s\n", err.Error())
        return
    }

	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		fmt.Printf("Can't parse my cert\n")
		return
	}

	conn, err := tls.Dial("tcp", server_addr, &tls.Config{
		RootCAs: x509.NewCertPool(),
		Certificates: []tls.Certificate{ cert },
		InsecureSkipVerify: true,
	})
	if err != nil {
		fmt.Printf("Can't connect: %s", err.Error())
		return
	}
	defer conn.Close()
	fmt.Fprintf(conn, "Secret Hello\n")
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

	if len(os.Args) > 1 {
		if os.Args[1] == "-tcpclient" {
			doTCPClient()
		} else if os.Args[1] == "-tcpserver" {
			doTCPServer()
		} else if os.Args[1] == "-tlsclient" {
			doTLSClient()
		} else if os.Args[1] == "-tlsserver" {
			doTLSServer()
		} else if os.Args[1] == "-taoclient" {
			//doTaoClient()
		} else if os.Args[1] == "-taoserver" {
			//doTaoServer()
		}
	}
}
