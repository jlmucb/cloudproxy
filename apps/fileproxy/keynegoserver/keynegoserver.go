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
	"errors"
	"time"
	"io/ioutil"
	"crypto/rand"
	"math/big"
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
func KeyNegoRequest(conn net.Conn, policyKey *tao.Keys,guard tao.Guard) (bool, error){
	fmt.Printf("keynegoerver: KeyNegoRequest\n")
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
	fmt.Print("keynegoserver, attest: ",  a)
	fmt.Print("\n")
	f, err := auth.UnmarshalForm(a.SerializedStatement)
	if err != nil {
		fmt.Printf("\nkeynegoserver: cant unmarshal a.SerializedStatement\n")
		return false, err
	}
	fmt.Print("\nkeynegoserver, unmarshaled serialized: %s\n",  f.String())
	fmt.Print("\n")

	var saysStatement *auth.Says
	if ptr, ok := f.(*auth.Says); ok {
		saysStatement = ptr
	} else if val, ok := f.(auth.Says); ok {
		saysStatement = &val
	}
	sf, ok := saysStatement.Message.(auth.Speaksfor)
	if(ok!=true) {
		fmt.Printf("keynegoserver: says doesnt have speaksfor message\n")
		return false, err
	}
	fmt.Print("keynegoserver, speaksfor: ",  sf)
	fmt.Print("\n")
	kprin, ok := sf.Delegate.(auth.Prin)
	if(ok!=true) {
		fmt.Printf("keynegoserver: speaksfor Delegate is not auth.Prin\n")
		return false, err
	}
	subjectPrin, ok:= sf.Delegator.(auth.Prin)
	if(ok!=true ) {
		fmt.Printf("keynegoserver: cant get subject principal\n")
		return false,errors.New("Cant get principal name from verifier") 
	}
	subjectnamestr:= subjectPrin.String()
	fmt.Printf("keynegoserver: subject principal name: %s\n", subjectnamestr)
	details:= tao.X509Details {
		Country: "US",
		Organization: "Google",
		CommonName: subjectnamestr, }
	subjectname:= tao.NewX509Name(details)
	template := &x509.Certificate{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		Version:            2, // x509v3
		// It's always allowed for self-signed certs to have serial 1.
		SerialNumber: new(big.Int).SetInt64(1),
		Subject:      *subjectname,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1 /* years */, 0 /* months */, 0 /* days */),
		KeyUsage:    x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		}
	verifier,err:= tao.FromPrincipal(kprin)
	clientDerCert, err := x509.CreateCertificate(rand.Reader, template, policyKey.Cert, 
					verifier.GetVerifierEc(),
	                                policyKey.SigningKey.GetSignerEc())
	if(err!=nil) {
		fmt.Printf("keynegoserver: cant create client certificate: %s\n", err)
		return false, err
	}
	err= ioutil.WriteFile("ClientCert", clientDerCert, os.ModePerm)

	// replace self signed cert in attest request
	newspeaksFor:= &auth.Speaksfor{
		Delegate:   auth.Bytes(clientDerCert),
		Delegator:  sf.Delegator,}
	truncSays:= &auth.Says{
		Speaker:  saysStatement.Speaker,
		// Time: ,
		// Expiration: ,
		Message: newspeaksFor,}

	delegator, ok := sf.Delegator.(auth.Prin)
	if !ok {
		fmt.Printf("keynegoserver: the delegator must be a principal")
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
	ra, err := tao.GenerateAttestation(policyKey.SigningKey, nil, *truncSays)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Couldn't attest to the new says statement:", err)
		return false, err
	}

	// Add an endorsement to this PrinExt Program hash so the receiver can check
	// it successfully against policy.
	endorsement := auth.Says{
		Speaker: policyKey.SigningKey.ToPrincipal(),
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
	ea, err := tao.GenerateAttestation(policyKey.SigningKey, nil, endorsement)
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

func  RequestLoop(conn net.Conn, policyKey *tao.Keys, guard tao.Guard) {
	fmt.Printf("keynegoserver: RequestLoop\n")

	defer conn.Close()
	var terminate bool
	var err error
	for {
		fmt.Printf("keynegoserver: about to call KeyNegoRequest\n")
		terminate, err= KeyNegoRequest(conn, policyKey, guard)
		if(terminate==true) {
			break;
		}
		if(err==nil) {
			fmt.Printf("keynegoserver: KeyNegoRequest returns no error\n")
		} else {
			fmt.Printf("keynegoserver: KeyNegoRequest returns error\n")
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
		fmt.Printf("keynegoserver: error: %s\n", err)
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
			fmt.Printf("keynegoserver: Couldn't accept a connection on %s: %s\n", *addr, err)
			return
		}
		fmt.Printf("keynegoserver: calling RequestLoop\n")
		go RequestLoop(conn, domain.Keys, domain.Guard)
	}
	fmt.Printf("keynegoserver: finishing\n")
}
