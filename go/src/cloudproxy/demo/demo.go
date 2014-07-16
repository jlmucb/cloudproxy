package main

import (
	"cloudproxy/tao"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var server_host = flag.String("host", "localhost", "address for client/server")
var server_port = flag.Int("port", 8123, "port for client/server")
var server_addr string // see main()
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
		fmt.Printf("Can't parse my cert\n")
		return
	}

	return
}

func setupTLSServer() (net.Listener, error) {
	cert, err := GenerateX509()
	if err != nil {
		fmt.Printf("Can't create key and cert: %s\n", err.Error())
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
		fmt.Printf("Can't create key and cert: %s\n", err.Error())
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
	fmt.Printf("Client connecting to %s using %s authentication.\n", server_addr, *demo_auth)
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
		fmt.Printf("Error connecting to %s: %s\n", server_addr, err.Error())
		return false
	}
	defer conn.Close()

	n, err := fmt.Fprintf(conn, "Hello\n")
	if err != nil {
		fmt.Printf("Can't write: ", err.Error())
		return false
	}
	msg, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Printf("Can't read: ", err.Error())
		return false
	}
	fmt.Printf("Got reply: %s\n", msg)
	return true
}

func doClient() {
	ping_good := 0
	ping_fail := 0
	for i := 0; i != *ping_count; i++ {  // negative means forever
		if doRequest() {
			ping_good++
		} else {
			ping_fail++
		}
		fmt.Printf("Client made %d connections, finished %d ok, %d bad pings\n",
			*ping_count, ping_good, ping_bad)
	}
}

func doResponse(conn net.Conn, ok <-chan bool) {
	defer conn.Close()

	// todo tao auth
	switch *demo_auth {
	case "tcp", "tls":
	case "tao":
	}

	msg, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Printf("Can't read: ", err.Error())
		conn.Close()
		ok <- false
		return
	}
	fmt.Printf("Got message: %s\n", msg)
	fmt.Fprintf(conn, "%s\n", response)
	conn.Close()
	ok <- true
}

func doServer(stop, ready, done chan<- bool) {
	var sock net.Listener
	var err error
	switch *demo_auth {
	case "tcp":
		sock, err = setupTCPServer()
	case "tls", "tao":
		sock, err = setupTLSServer()
	}
	if err != nil {
		fmt.Printf("Server can't listen at %s: %s\n", server_addr, err.Error())
		ready <- false
		done <- true
		return
	}
	defer sock.Close()
	fmt.Printf("Server listening at %s using %s authentication.\n", server_addr, *demo_auth)
	ready <- true

	var pings chan bool
	conn_count := 0
	ping_good := 0
	ping_fail := 0

	for conn_count = 0; conn_count != *ping_count; conn_count++ { // negative means forever
		conn, err := sock.Accept()
		if err != nil {
			fmt.Printf("Can't accept connection: %s\n", err.Error())
			pings <- false
			return
		}
		go doResponse(conn, pings)
	}


	for conn_count < *ping_count {
		// update stats, otherwise handle new connection
		select {
		case ok := <-pings:
			if ok {
				ping_good++
			} else {
				ping_fail++
			}
		default:
			conn, err := sock.Accept()
			if err != nil {
				fmt.Printf("Can't accept connection: %s\n", err.Error())
				break loop
			}
			// Handle connections in a new goroutine.
			conn_count++
			go doResponse(conn, pings)
		}
	}

	sock.Close()

	for ping_good+ping_fail < conn_count {
		// update stats
		ok := <-pings
		if ok {
			ping_good++
		} else {
			ping_fail++
		}
		fmt.Printf("Server handled %d connections, finished %d ok, %d bad pings\n",
			conn_count, ping_good, ping_bad)
	}

	server_ok <- (ping_good == *ping_count)
}

// Tao Host demo

func hostTaoDemo() error {
	var err error

	var name string
	name, err = tao.Host.GetTaoName()
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

	var random []byte
	random, err = tao.Host.GetRandomBytes(10)
	if err != nil {
		return err
	}
	fmt.Printf("Random bytes  : % x\n", random)

	var secret []byte
	secret, err = tao.Host.GetSharedSecret(10, tao.SharedSecretPolicyDefault)
	if err != nil {
		return err
	}
	fmt.Printf("Shared secret : % x\n", secret)

	var sealed []byte
	sealed, err = tao.Host.Seal(random, tao.SealPolicyDefault)
	if err != nil {
		return err
	}
	fmt.Printf("Sealed bytes  : % x\n", sealed)

	var unsealed []byte
	var policy string
	unsealed, policy, err = tao.Host.Unseal(sealed)
	if err != nil {
		return err
	}
	if policy != tao.SealPolicyDefault {
		return errors.New("Unexpected policy on unseal")
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
		fmt.Printf("Unrecognized authentication mode: %s\n", *demo_auth)
		return
	}

	fmt.Printf("Go Tao Demo\n")

	if tao.Host == nil {
		return errors.New("No host Tao available")
	}

	if *local_mode || (!*client_mode && !*server_mode) {
		err := hostTaoDemo()
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			return
		}
	}

	var server_stop, server_ready, server_done chan bool
	var client_done chan bool

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

}
