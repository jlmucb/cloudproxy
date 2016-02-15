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
	"errors"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
)

var network = flag.String("network", "tcp", "The network to use for connections")
var addr = flag.String("addr", "localhost:8124", "The address to listen on")
var domainPass = flag.String("password", "xxx", "The domain password")
var configPath = flag.String("config",
	"SimpleDomain/domain.simpleexample/tao.config", "The Tao domain config")

var SerialNumber int64

func IsAuthenticationValid(name *string) bool {
	log.Printf("simpledomainservice, IsAuthenticationValid name is %s\n", *name)
	if name == nil {
		return false
	}
	log.Printf("simpledomainservice, IsAuthenticationValid returning true\n")
	return true
}

// First return is terminate flag.
func DomainRequest(conn net.Conn, policyKey *tao.Keys, guard tao.Guard) (bool, error) {
	log.Printf("simpledomainserver: request\n")

	// Expect an attestation from the client.
	ms := util.NewMessageStream(conn)
	var a tao.Attestation
	if err := ms.ReadMessage(&a); err != nil {
		log.Printf("Couldn't read attestation from channel:", err)
		log.Printf("\n")
		return false, err
	}

	peerCert := conn.(*tls.Conn).ConnectionState().PeerCertificates[0]
	if err := tao.ValidatePeerAttestation(&a, peerCert, guard); err != nil {
		log.Printf("Couldn't validate peer attestation:", err)
		return false, err
	}

	// Sign cert and put it in attestation statement
	// a consists of serialized statement, sig and SignerInfo
	// a is a says speaksfor, Delegate of speaksfor is cert and should be DER encoded

	// Get underlying says
	f, err := auth.UnmarshalForm(a.SerializedStatement)
	if err != nil {
		log.Printf("simpledomainservice: can't unmarshal a.SerializedStatement\n")
		return false, err
	}

	var saysStatement *auth.Says
	if ptr, ok := f.(*auth.Says); ok {
		saysStatement = ptr
	} else if val, ok := f.(auth.Says); ok {
		saysStatement = &val
	}
	sf, ok := saysStatement.Message.(auth.Speaksfor)
	if ok != true {
		log.Printf("simpledomainservice: says doesnt have speaksfor message\n")
		return false, err
	}

	log.Print("simpledomainservice, speaksfor: ", sf)
	log.Print("\n")
	kprin, ok := sf.Delegate.(auth.Prin)
	if ok != true {
		log.Printf("simpledomainservice: speaksfor Delegate is not auth.Prin\n")
		return false, err
	}
	subjectPrin, ok := sf.Delegator.(auth.Prin)
	if ok != true {
		log.Printf("simpledomainservice: can't get subject principal\n")
		return false, errors.New("Can't get principal name from verifier")
	}
	subjectnamestr := subjectPrin.String()
	verified := IsAuthenticationValid(&subjectnamestr)
	if !verified {
		log.Printf("simpledomainservice: name verification failed\n")
		return false, err
	}
	log.Printf("simpledomainservice, authenticated principal name: %s\n", subjectnamestr)

	// Sign program certificate.
	us := "US"
	google := "Google"
	localhost := "localhost"
	details := tao.X509Details{
		Country:            &us,
		Organization:       &google,
		OrganizationalUnit: &subjectnamestr,
		CommonName:         &localhost,
	}
	subjectname := tao.NewX509Name(&details)
	SerialNumber = SerialNumber + 1
	verifier, err := tao.FromPrincipal(kprin)
	if err != nil {
		return false, errors.New("can't get principal from kprin")
	}
	log.Printf("verifier: %x\n", verifier)
	clientCert, err := policyKey.SigningKey.CreateSignedX509(policyKey.Cert, int(SerialNumber), verifier, subjectname)
	if err != nil {
		log.Printf("simpledomainservice: can't create client certificate: %s\n", err)
		return false, err
	}
	clientDerCert := clientCert.Raw
	err = ioutil.WriteFile("ClientCert", clientDerCert, os.ModePerm)

	nowTime := time.Now().UnixNano()
	expireTime := time.Now().AddDate(1, 0, 0).UnixNano()

	// Replace self signed cert in attest request
	newspeaksFor := &auth.Speaksfor{
		Delegate:  auth.Bytes(clientDerCert),
		Delegator: sf.Delegator}
	keynegoSays := &auth.Says{
		Speaker:    policyKey.SigningKey.ToPrincipal(),
		Time:       &nowTime,
		Expiration: &expireTime,
		Message:    newspeaksFor}

	delegator, ok := sf.Delegator.(auth.Prin)
	if !ok {
		log.Printf("simpledomainservice: delegator must be principal")
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
	ra, err := tao.GenerateAttestation(policyKey.SigningKey, nil, *keynegoSays)
	if err != nil {
		log.Printf("Couldn't attest to the new says statement:", err)
		return false, err
	}

	// Add an endorsement to this PrinExt Program hash so the receiver can
	//  check it successfully against policy.
	endorsement := auth.Says{
		Speaker: policyKey.SigningKey.ToPrincipal(),
		Message: auth.Pred{
			Name: "TrustedProgramHash",
			Arg:  []auth.Term{auth.PrinTail{Ext: []auth.PrinExt{prog}}},
		},
	}
	if keynegoSays.Time != nil {
		i := *keynegoSays.Time
		endorsement.Time = &i
	}
	if keynegoSays.Expiration != nil {
		i := *keynegoSays.Expiration
		endorsement.Expiration = &i
	}
	ea, err := tao.GenerateAttestation(policyKey.SigningKey, nil, endorsement)
	if err != nil {
		log.Printf("Couldn't generate an endorsement for this program:", err)
		return false, err
	}
	eab, err := proto.Marshal(ea)
	if err != nil {
		log.Printf("Couldn't marshal an endorsement:", err)
		return false, err
	}
	ra.SerializedEndorsements = [][]byte{eab}

	if _, err := ms.WriteMessage(ra); err != nil {
		log.Printf("Couldn't return the attestation on the channel:", err)
		log.Printf("\n")
		return false, err
	}

	return false, nil
}

func main() {
	flag.Parse()
	domain, err := tao.LoadDomain(*configPath, []byte(*domainPass))
	if domain == nil {
		log.Printf("simpledomainservice: no domain %s %s %s\n",
			*configPath, *domainPass, err)
		return
	} else if err != nil {
		log.Printf("simpledomainservice: Couldn't load the config path %s: %s\n", *configPath, err)
		return
	}
	log.Printf("Loaded domain\n")

	// Set up temporary keys for the connection, since the only thing that
	// matters to the remote client is that they receive a correctly-signed new
	// attestation from the policy key.
	// JLM:  I left this in place but I'm not sure what a TLS connection with a
	//   self signed Cert buys in terms of security.
	//   The security of this protocol should not depend on the
	//   confidentiality or intergity of the channel.  All that said, if we
	//   do ever distribute a signed simpledomainservice cert
	// for this TLS channel, it would be good.
	keys, err := tao.NewTemporaryKeys(tao.Signing)
	if keys == nil || err != nil {
		log.Fatalln("simpledomainservice: Couldn't set up temporary keys for the connection:", err)
		return
	}
	keys.Cert, err = keys.SigningKey.CreateSelfSignedX509(&pkix.Name{
		Organization: []string{"Google Tao Demo"}})
	if err != nil {
		log.Fatalln("simpledomainservice: Couldn't set up a self-signed cert:", err)
		return
	}
	SerialNumber = int64(time.Now().UnixNano()) / (1000000)
	policyKey, err := tao.NewOnDiskPBEKeys(tao.Signing,
		[]byte(*domainPass), "policy_keys", nil)
	if err != nil {
		log.Fatalln("simpledomainservice: Couldn't get policy key\n", err)
	}
	log.Printf("simpledomainservice: Policy key %x\n: ", policyKey)

	tlsc, err := tao.EncodeTLSCert(keys)
	if err != nil {
		log.Fatalln("simpledomainservice: Couldn't encode a TLS cert:", err)
	}
	conf := &tls.Config{
		RootCAs:            x509.NewCertPool(),
		Certificates:       []tls.Certificate{*tlsc},
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequireAnyClientCert,
	}
	sock, err := tls.Listen(*network, *addr, conf)
	if err != nil {
		log.Printf("simpledomainservice: error: %s\n", err)
	}
	if sock == nil {
		log.Printf("simpledomainservice: Empty socket, terminating\n")
		return
	}
	defer sock.Close()

	log.Printf("simpledomainservice: accepting connections\n")
	for {
		conn, err := sock.Accept()
		if conn == nil {
			log.Printf("simpledomainservice: Empty connection\n")
			return
		} else if err != nil {
			log.Printf("simpledomainservice: Couldn't accept a connection on %s: %s\n", *addr, err)
			return
		}
		log.Printf("simpledomainservice: calling RequestLoop\n")
		go DomainRequest(conn, policyKey, domain.Guard)
	}
	log.Printf("simpledomainservice: finishing\n")
}
