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

package net

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"testing"

	"github.com/jlmucb/cloudproxy/tao"
)

func newNetKeys(t *testing.T, ta tao.Tao, org string) (*tao.Keys, *tls.Config) {
	var keys *tao.Keys
	var err error
	if ta != nil {
		keys, err = tao.NewTemporaryTaoDelegatedKeys(tao.Signing, ta)
	} else {
		keys, err = tao.NewTemporaryKeys(tao.Signing)
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

func setUpListener(t *testing.T) (net.Listener, *tao.Keys, tao.Tao) {
	st, err := tao.NewSoftTao("", nil)
	if err != nil {
		t.Fatalf("couldn't create a new SoftTao: %s", err)
	}

	soft, ok := st.(*tao.SoftTao)
	if !ok {
		t.Fatalf("couldn't down-cast the Tao to a SoftTao")
	}

	keys, conf := newNetKeys(t, st, "Net Test")

	// For a simple Listen test, use the LiberalGuard.
	l, err := Listen("tcp", "127.0.0.1:0", conf, tao.LiberalGuard, soft.GetVerifier(), keys.Delegation)
	if err != nil {
		t.Fatalf("couldn't set up a Tao listener: %s", err)
	}

	return l, keys, st
}

func TestListen(t *testing.T) {
	// Run a basic test to make sure the listener can be created.
	l, _, _ := setUpListener(t)
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

func TestClientServer(t *testing.T) {
	l, _, st := setUpListener(t)
	addr := l.Addr()
	ch := make(chan bool)

	count := 16
	go runListener(t, l, count, ch)

	// Create a client to connect to the server and send and receive a
	// message.
	verifier := st.(*tao.SoftTao).GetVerifier()

	ck, _ := newNetKeys(t, st, "Net Test")

	c, err := DialWithKeys("tcp", addr.String(), tao.LiberalGuard, verifier, ck)
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

func runTCCA(t *testing.T, l net.Listener, pk *tao.Keys, g tao.Guard, ch chan<- bool) {
	conn, err := l.Accept()
	if err != nil {
		t.Fatalf("couldn't accept a connection for tcca: %s", err)
	}

	HandleCARequest(conn, pk.SigningKey, g)
	ch <- true
}

func TestCARequestAttestation(t *testing.T) {
	// Create a temporary key as the policy key.
	pk, err := tao.NewTemporaryKeys(tao.Signing)
	if err != nil {
		t.Fatalf("couldn't set up a temporary policy key: %s", err)
	}

	_, caconf := newNetKeys(t, nil, "Net Test")

	cal, err := tls.Listen("tcp", "127.0.0.1:0", caconf)
	caAddr := cal.Addr()

	// For the simple test, use a LiberalGuard in the CA.
	ch := make(chan bool)
	go runTCCA(t, cal, pk, tao.LiberalGuard, ch)

	// Set up some keys to be attested.
	st, err := tao.NewSoftTao("", nil)
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
	pk, err := tao.NewTemporaryKeys(tao.Signing)
	if err != nil {
		t.Fatalf("couldn't set up a temporary policy key: %s", err)
	}

	_, caconf := newNetKeys(t, nil, "Net Test")

	cal, err := tls.Listen("tcp", "127.0.0.1:0", caconf)
	caAddr := cal.Addr()

	// For the simple test, use a LiberalGuard in the CA.
	ch := make(chan bool)
	go runTCCA(t, cal, pk, tao.LiberalGuard, ch)

	// Set up some keys to be attested.
	st, err := tao.NewSoftTao("", nil)
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
