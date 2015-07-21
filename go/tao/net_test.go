//  Copyright (c) 2015, Google Inc.  All rights reserved.
//
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

package tao

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"os"
	"testing"

	"github.com/jlmucb/cloudproxy/go/util"
)

func newNetKeys(t *testing.T, ta Tao, org string) (*Keys, *tls.Config) {
	var keys *Keys
	var err error
	if ta != nil {
		keys, err = NewTemporaryTaoDelegatedKeys(Signing, ta)
	} else {
		keys, err = NewTemporaryKeys(Signing)
	}
	if err != nil {
		t.Fatalf("couldn't create new temporary delegated keys: %s", err)
	}

	keys.Cert, err = keys.SigningKey.CreateSelfSignedX509(&pkix.Name{
		Organization: []string{org}})
	if err != nil {
		t.Fatalf("couldn't create a self-signed certificate from the keys: %s", err)
	}

	tlsc, err := EncodeTLSCert(keys)
	if err != nil {
		t.Fatalf("couldn't encode TLS cert from the keys")
	}

	conf := &tls.Config{
		RootCAs:            x509.NewCertPool(),
		Certificates:       []tls.Certificate{*tlsc},
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequireAnyClientCert,
	}

	return keys, conf
}

func setUpListener(t *testing.T, anonymous bool) (net.Listener, *Keys, Tao) {
	st, err := NewSoftTao("", nil)
	if err != nil {
		t.Fatalf("couldn't create a new SoftTao: %s", err)
	}

	soft, ok := st.(*SoftTao)
	if !ok {
		t.Fatalf("couldn't down-cast the Tao to a SoftTao")
	}

	keys, conf := newNetKeys(t, st, "Net Test")

	// For a simple Listen test, use the LiberalGuard.
	var l net.Listener
	if !anonymous {
		l, err = Listen("tcp", "127.0.0.1:0", conf, LiberalGuard, soft.GetVerifier(), keys.Delegation)
	} else {
		l, err = ListenAnonymous("tcp", "127.0.0.1:0", conf, LiberalGuard, soft.GetVerifier(), keys.Delegation)
	}
	if err != nil {
		t.Fatalf("couldn't set up a Tao listener: %s", err)
	}

	return l, keys, st
}

func TestListener(t *testing.T) {
	// Run a basic test to make sure the listener can be created.
	l, _, _ := setUpListener(t, false)
	l.Close()
}

func TestAnonymousListener(t *testing.T) {
	// Run a basic test to make sure the anonymousListener can be created.
	l, _, _ := setUpListener(t, true)
	l.Close()
}

// getMessage gets all the bytes of a message, using a fixed-size buffer.
func getMessage(t *testing.T, c net.Conn, count int) []byte {
	b := make([]byte, count)
	n, err := c.Read(b)
	if err != nil {
		t.Fatalf("couldn't read from the connection: %s", err)
	}
	if n != count {
		t.Fatalf("failed to read the right number of bytes: expected %d, but got %d", count, n)
	}

	return b
}

// runListener accepts a single connection and echo the message received on it.
// This function takes ownership of the net.Listener and closes it.
func runListener(t *testing.T, l net.Listener, count int, ch chan<- bool) {
	defer l.Close()
	c, err := l.Accept()
	if err != nil {
		t.Fatalf("couldn't accept a network connection: %s", err)
	}
	defer c.Close()
	msg := getMessage(t, c, count)

	if _, err := c.Write(msg); err != nil {
		t.Fatalf("couldn't write the bytes back on the connection: %s", err)
	}

	ch <- true
}

// Test TLS handshake between two Tao-delegated peers.
func TestTaoHandshake(t *testing.T) {
	l, _, st := setUpListener(t, false)
	addr := l.Addr()
	ch := make(chan bool)

	count := 16
	go runListener(t, l, count, ch)

	// Create a client to connect to the server and send and receive a
	// message.
	verifier := st.(*SoftTao).GetVerifier()

	ck, _ := newNetKeys(t, st, "Net Test")

	c, err := Dial("tcp", addr.String(), LiberalGuard, verifier, ck)
	if err != nil {
		t.Fatalf("couldn't dial the server using Tao networking: %s", err)
	}

	b := make([]byte, count)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("couldn't read bytes to send to the server: %s", err)
	}

	if _, err := c.Write(b); err != nil {
		t.Fatalf("couldn't send the bytes to the server: %s", err)
	}

	res := getMessage(t, c, count)
	if !bytes.Equal(res, b) {
		t.Fatal("the received bytes didn't match the original bytes")
	}

	// Wait for the server to finish.
	<-ch
}

// Test TLS handshake between a Tao-delegated server and anonymous client.
func TestAnonymousTaoHandshake(t *testing.T) {
	l, _, st := setUpListener(t, true)
	addr := l.Addr()
	ch := make(chan bool)

	count := 16
	go runListener(t, l, count, ch)

	// Create a client to connect to the server and send and receive a
	// message.
	verifier := st.(*SoftTao).GetVerifier()

	c, err := Dial("tcp", addr.String(), LiberalGuard, verifier, nil)
	if err != nil {
		t.Fatalf("couldn't dial the server using Tao networking: %s", err)
	}

	b := make([]byte, count)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("couldn't read bytes to send to the server: %s", err)
	}

	if _, err := c.Write(b); err != nil {
		t.Fatalf("couldn't send the bytes to the server: %s", err)
	}

	res := getMessage(t, c, count)
	if !bytes.Equal(res, b) {
		t.Fatal("the received bytes didn't match the original bytes")
	}

	// Wait for the server to finish.
	<-ch
}

func runTCCA(t *testing.T, l net.Listener, pk *Keys, g Guard, ch chan<- bool) {
	conn, err := l.Accept()
	if err != nil {
		t.Fatalf("couldn't accept a connection for tcca: %s", err)
	}

	HandleCARequest(conn, pk.SigningKey, g)
	ch <- true
}

func TestCARequestAttestation(t *testing.T) {
	// Create a temporary key as the policy key.
	pk, err := NewTemporaryKeys(Signing)
	if err != nil {
		t.Fatalf("couldn't set up a temporary policy key: %s", err)
	}

	cal, err := net.Listen("tcp", "127.0.0.1:0")
	caAddr := cal.Addr()

	// For the simple test, use a LiberalGuard in the CA.
	ch := make(chan bool)
	go runTCCA(t, cal, pk, LiberalGuard, ch)

	// Set up some keys to be attested.
	st, err := NewSoftTao("", nil)
	if err != nil {
		t.Fatalf("couldn't create a new SoftTao: %s", err)
	}

	keys, _ := newNetKeys(t, st, "Net Test")

	_, err = RequestAttestation("tcp", caAddr.String(), keys, pk.VerifyingKey)
	if err != nil {
		t.Fatalf("failed to get an attestation from the CA: %s", err)
	}

	// Wait for the CA to finish
	<-ch
}

func TestCARequestTruncatedAttestation(t *testing.T) {
	// Create a temporary key as the policy key.

	pk, err := NewTemporaryKeys(Signing)
	if err != nil {
		t.Fatalf("couldn't set up a temporary policy key: %s", err)
	}

	cal, err := net.Listen("tcp", "127.0.0.1:0")
	caAddr := cal.Addr()

	// For the simple test, use a LiberalGuard in the CA.
	ch := make(chan bool)
	go runTCCA(t, cal, pk, LiberalGuard, ch)

	// Set up some keys to be attested.
	st, err := NewSoftTao("", nil)
	if err != nil {
		t.Fatalf("couldn't create a new SoftTao: %s", err)
	}

	keys, _ := newNetKeys(t, st, "Net Test")

	_, err = RequestTruncatedAttestation("tcp", caAddr.String(), keys, pk.VerifyingKey)
	if err != nil {
		t.Fatalf("failed to get a truncated attestation from the CA: %s", err)
	}

	// Wait for the CA to finish
	<-ch
}

func TestCARequestDatalogRules(t *testing.T) {
	cal, err := net.Listen("tcp", "127.0.0.1:0")
	caAddr := cal.Addr()

	guard, keys, tmpDir, err := makeDatalogGuard()
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	ch := make(chan bool)

	// Nominal test
	go runTCCA(t, cal, keys, guard, ch)
	_, err = RequestDatalogRules("tcp", caAddr.String(), keys.VerifyingKey)
	if err != nil {
		t.Errorf("Failed to get datalog rules from CA: %s", err)
	}
	<-ch

	// Signature shouldn't verify
	badKeys, _ := NewTemporaryKeys(Signing)
	go runTCCA(t, cal, badKeys, guard, ch)
	_, err = RequestDatalogRules("tcp", caAddr.String(), keys.VerifyingKey)
	if err == nil {
		t.Error("Signature verified, should have failed")
	} else {
		t.Logf("Signature invalid!, %s", err)
	}
	<-ch
}

func TestCARequestACLSet(t *testing.T) {
	cal, err := net.Listen("tcp", "127.0.0.1:0")
	caAddr := cal.Addr()

	// Run TaoCA with a DatalogGuard.
	guard, keys, tmpDir, err := makeACLGuard()
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	ch := make(chan bool)

	// Nominal test.
	go runTCCA(t, cal, keys, guard, ch)
	_, err = RequestACLSet("tcp", caAddr.String(), keys.VerifyingKey)
	if err != nil {
		t.Fatalf("Failed to get ACL set from CA: %s", err)
	}
	<-ch

	// Signature shouldn't verify
	badKeys, _ := NewTemporaryKeys(Signing)
	go runTCCA(t, cal, badKeys, guard, ch)
	_, err = RequestACLSet("tcp", caAddr.String(), keys.VerifyingKey)
	if err == nil {
		t.Error("Signature verified, should have failed")
	} else {
		t.Logf("Signature invalid!, %s", err)
	}
	<-ch
}

func TestInvalidRequest(t *testing.T) {
	cal, err := net.Listen("tcp", "127.0.0.1:0")
	caAddr := cal.Addr()

	guard, keys, tmpDir, err := makeDatalogGuard()
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	ch := make(chan bool)

	// Test an invalid request.
	go runTCCA(t, cal, keys, guard, ch)

	conn, err := net.Dial("tcp", caAddr.String())
	if err != nil {
		t.Fatal("Failed to connect to TaoCA.")
	}
	defer conn.Close()

	// Bad CArequest, no value for bad_req.Attesation
	badReq := new(CARequest)
	badReq.Type = CAType_ATTESTATION.Enum()

	ms := util.NewMessageStream(conn)
	if _, err = ms.WriteMessage(badReq); err != nil {
		t.Logf("Failed to write to message stream: %s", err)
	}

	// Receive response.
	var resp CAResponse
	if err := ms.ReadMessage(&resp); err != nil {
		t.Fatalf("Failed to read from message stream: %s", err)
	}

	if *resp.Type != CAType_UNDEFINED {
		t.Fatalf("Response should have been UNDEFINED, got %s", resp.Type.String())
	}

	<-ch
}
