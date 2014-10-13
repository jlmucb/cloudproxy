// Copyright (c) 2014, Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"os"
	"net"
	"code.google.com/p/goprotobuf/proto"
	"github.com/jlmucb/cloudproxy/tao"
	taonet "github.com/jlmucb/cloudproxy/tao/net"
	"github.com/jlmucb/cloudproxy/tao/auth"
	"github.com/jlmucb/cloudproxy/util"
)

var network = flag.String("network", "tcp", "The network to use for connections")
var addr = flag.String("addr", "localhost:8124", "The address to listen on")
var domainPass = flag.String("password", "BogusPass", "The domain password for the policy key")
var configPath = flag.String("config", "tao.config", "The Tao domain config")


func KeyNegoRequest(conn net.Conn, s *tao.Signer, guard tao.Guard, v *tao.Verifier) {
	defer conn.Close()

	// Expect an attestation from the client.
	ms := util.NewMessageStream(conn)
	var a tao.Attestation
	if err := ms.ReadMessage(&a); err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't read attestation from channel:", err)
		return
	}

	peerCert := conn.(*tls.Conn).ConnectionState().PeerCertificates[0]
	if err := taonet.ValidatePeerAttestation(&a, peerCert, guard); err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't validate peer attestation:", err)
		return
	}

	// sign cert and put it in attestation statement
	// a consists of serialized statement, sig and SignerInfo
	// a is a says speaksfor, Delegate of speaksfor is cert and should be DER encoded

	// get underlying says
	f, err := auth.UnmarshalForm(a.SerializedStatement)
	if err != nil {
		fmt.Printf("cant unmarshal a.SerializedStatement\n")
		return
	}

	var saysStatement *auth.Says
	if ptr, ok := f.(*auth.Says); ok {
		saysStatement = ptr
	} else if val, ok := f.(auth.Says); ok {
		saysStatement = &val
	}
	sf, ok := saysStatement.Message.(auth.Speaksfor)
	if(ok!=true) {
		fmt.Printf("says doesnt have speaksfor message\n")
		return
	}
	kprin, ok := sf.Delegate.(auth.Prin)
	if(ok!=true) {
		fmt.Printf("speaksfor Delegate is not auth.Prin\n")
		return
	}
	keyTerm, ok:=  kprin.Key.(auth.Term)
	if(ok!=true) {
		fmt.Printf("kprin.Term is not a Bytes\n")
		return
	}
	derCert:= keyTerm.(auth.Bytes)
	fmt.Printf("Cert has %d bytes\n", len(derCert))
	subjCert, err := x509.ParseCertificate(derCert)
	if subjCert == nil || err != nil {
		fmt.Printf("cant parse certificate\n")
		return
	}

	// get new cert signed by me
	subject:= subjCert.Subject
	signedCert, err:= s.CreateSignedX509(subjCert, 01, v, &subject)
	if signedCert == nil || err != nil {
		fmt.Printf("cant sign certificate\n")
		return
	}

	// replace self signed cert in attest request
	newspeaksFor:= &auth.Speaksfor{
		Delegate:   auth.Bytes(signedCert.Raw),
		Delegator:  sf.Delegator,}
	truncSays:= &auth.Says{
		Speaker:  saysStatement.Speaker,
		// Time: ,
		// Expiration: ,
		Message: newspeaksFor,}

	delegator, ok := sf.Delegator.(auth.Prin)
	if !ok {
		fmt.Printf("the delegator must be a principal")
		return;
	}
	var prog auth.PrinExt
	found := false
	for _, sprin := range delegator.Ext {
		if !found && (sprin.Name == "Program") {
			found = true
			prog = sprin
		}
		if found {
			kprin.Ext = append(kprin.Ext, sprin)
		}
	}
	ra, err := tao.GenerateAttestation(s, nil, *truncSays)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't attest to the new says statement:", err)
		return
	}

	// Add an endorsement to this PrinExt Program hash so the receiver can check
	// it successfully against policy.
	endorsement := auth.Says{
		Speaker: s.ToPrincipal(),
		Message: auth.Pred{
			Name: "TrustedProgramHash",
			Arg:  []auth.Term{auth.PrinTail{Ext: []auth.PrinExt{prog}}},
		},
	}
	if truncSays.Time != nil {
		i := *truncSays.Time
		endorsement.Time = &i
	}
	if truncSays.Expiration != nil {
		i := *truncSays.Expiration
		endorsement.Expiration = &i
	}
	ea, err := tao.GenerateAttestation(s, nil, endorsement)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't generate an endorsement for this program:", err)
		return
	}
	eab, err := proto.Marshal(ea)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't marshal an endorsement:", err)
		return
	}
	ra.SerializedEndorsements = [][]byte{eab}

	if _, err := ms.WriteMessage(ra); err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't return the attestation on the channel:", err)
		return
	}

	return
}


func main() {
	flag.Parse()
	domain, err := tao.LoadDomain(*configPath, []byte(*domainPass))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't load the config path %s: %s\n", *configPath, err)
		return
	}

	// Set up temporary keys for the connection, since the only thing that
	// matters to the remote client is that they receive a correctly-signed new
	// attestation from the policy key.
	// JLM:  I left this in place but I'm not sure what a TLS connection with a 
	//   self signed Cert buys in terms of security.  The security of this protocol should
	//   not depend on the confidentiality or intergity of the channel.  All that said,
	//   if we do ever distribute a signed keynegoserver cert for this TLS channel, it would
	//   be good.
	keys, err := tao.NewTemporaryKeys(tao.Signing)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't set up temporary keys for the connection:", err)
		return
	}
	keys.Cert, err = keys.SigningKey.CreateSelfSignedX509(&pkix.Name{
		Organization: []string{"Google Tao Demo"}})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't set up a self-signed cert:", err)
	return
	}

	tlsc, err := taonet.EncodeTLSCert(keys)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't encode a TLS cert:", err)
		return
	}
	conf := &tls.Config{
		RootCAs:            x509.NewCertPool(),
		Certificates:       []tls.Certificate{*tlsc},
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequireAnyClientCert,
	}
	sock, err := tls.Listen(*network, *addr, conf)

	fmt.Println("keynegoserver: accepting connections")
	for {
		conn, err := sock.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Couldn't accept a connection on %s: %s\n", *addr, err)
			return
		}

		go KeyNegoRequest(conn, domain.Keys.SigningKey, domain.Guard, domain.Keys.VerifyingKey)
	}
}
