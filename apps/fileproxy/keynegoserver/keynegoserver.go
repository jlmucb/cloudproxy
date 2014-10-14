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
var domainPass = flag.String("password", "nopassword", "The domain password for the policy key")
var configPath = flag.String("config", "tao.config", "The Tao domain config")

// return is terminate, error
func KeyNegoRequest(conn net.Conn, s *tao.Signer, guard tao.Guard, v *tao.Verifier) (bool, error){
	fmt.Printf("KeyNegoRequest\n")
	// Expect an attestation from the client.
	ms := util.NewMessageStream(conn)
	var a tao.Attestation
	if err := ms.ReadMessage(&a); err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't read attestation from channel:", err)
		return false, err
	}

	peerCert := conn.(*tls.Conn).ConnectionState().PeerCertificates[0]
	if err := taonet.ValidatePeerAttestation(&a, peerCert, guard); err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't validate peer attestation:", err)
		return false, err
	}

	// sign cert and put it in attestation statement
	// a consists of serialized statement, sig and SignerInfo
	// a is a says speaksfor, Delegate of speaksfor is cert and should be DER encoded

	// get underlying says
	f, err := auth.UnmarshalForm(a.SerializedStatement)
	if err != nil {
		fmt.Printf("cant unmarshal a.SerializedStatement\n")
		return false, err
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
		return false, err
	}
	kprin, ok := sf.Delegate.(auth.Prin)
	if(ok!=true) {
		fmt.Printf("speaksfor Delegate is not auth.Prin\n")
		return false, err
	}
	keyTerm, ok:=  kprin.Key.(auth.Term)
	if(ok!=true) {
		fmt.Printf("kprin.Term is not a Bytes\n")
		return false, err
	}
	derCert:= keyTerm.(auth.Bytes)
	fmt.Printf("Cert has %d bytes\n", len(derCert))
	subjCert, err := x509.ParseCertificate(derCert)
	if subjCert == nil || err != nil {
		fmt.Printf("cant parse certificate\n")
		return false, err
	}

	// get new cert signed by me
	subject:= subjCert.Subject
	signedCert, err:= s.CreateSignedX509(subjCert, 01, v, &subject)
	if signedCert == nil || err != nil {
		fmt.Printf("cant sign certificate\n")
		return false, err
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
		return false, err
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
		return false, err
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
		return false, err
	}
	eab, err := proto.Marshal(ea)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't marshal an endorsement:", err)
		return false, err
	}
	ra.SerializedEndorsements = [][]byte{eab}

	if _, err := ms.WriteMessage(ra); err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't return the attestation on the channel:", err)
		return false, err
	}

	return false, nil
}

func  RequestLoop(conn net.Conn, s *tao.Signer, guard tao.Guard, v *tao.Verifier) {
	fmt.Printf("RequestLoop\n")

	// defer conn.Close()
	var terminate bool
	var err error
	for {
		terminate, err= KeyNegoRequest(conn, s, guard, v)
		if(terminate==true) {
			break;
		}
		if(err==nil) {
			fmt.Printf("KeyNegoRequest returns no error\n")
		} else {
			fmt.Printf("KeyNegoRequest returns error\n")
		}
		if(terminate==true) {
			break;
		}
	}
	return
}

func main() {
	flag.Parse()
	domain, err := tao.LoadDomain(*configPath, []byte(*domainPass))
	if domain == nil {
		fmt.Printf("keynegoserver: no domain\n")
		return
	} else if err != nil {
		fmt.Printf("keynegoserver: Couldn't load the config path %s: %s\n", *configPath, err)
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
	if keys == nil || err != nil {
		fmt.Printf("keynegoserver: Couldn't set up temporary keys for the connection:", err)
		return
	}
	keys.Cert, err = keys.SigningKey.CreateSelfSignedX509(&pkix.Name{
		Organization: []string{"Google Tao Demo"}})
	if err != nil {
		fmt.Printf("keynegoserver: Couldn't set up a self-signed cert:", err)
	return
	}

	tlsc, err := taonet.EncodeTLSCert(keys)
	if err != nil {
		fmt.Printf("keynegoserver: Couldn't encode a TLS cert:", err)
		return
	}
	conf := &tls.Config{
		RootCAs:            x509.NewCertPool(),
		Certificates:       []tls.Certificate{*tlsc},
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequireAnyClientCert,
	}
	sock, err := tls.Listen(*network, *addr, conf)
	if(err!=nil) {
		fmt.Printf("error: %s\n", err)
	}
	if(sock==nil) {
		fmt.Printf("keynegoserver: Empty socket, terminating\n")
		return
	}
	defer sock.Close();

	fmt.Printf("keynegoserver: accepting connections\n")
	for {
		conn, err := sock.Accept()
		if conn == nil  {
			fmt.Printf("keynegoserver: Empty connection\n")
			return
		} else if err != nil {
			fmt.Printf("keynegoserver: Couldn't accept a connection\n")
			// fmt.Printf("keynegoserver: Couldn't accept a connection on %s: %s\n", *addr, err)
			return
		}
		fmt.Printf("keynegoserver: calling RequestLoop\n")
		go RequestLoop(conn, domain.Keys.SigningKey, domain.Guard, domain.Keys.VerifyingKey)
		break;
	}
	fmt.Printf("keynegoserver: finishing\n")
}
