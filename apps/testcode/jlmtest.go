// Copyright (c) 2014, Kevin Walsh.  All rights reserved.
// Copyright (c) 2014, Google COrporation.  All rights reserved.
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
// jlmtest.go

package main

import (
	//"bufio"
	//"crypto/tls"
	//"crypto/x509"
	//"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	//"net"
	"code.google.com/p/goprotobuf/proto"
	"os"
	//"strings"

	"github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/tao/auth"
	//taonet "github.com/jlmucb/cloudproxy/tao/net"
)

var ca = flag.String("ca", "", "address for Tao CA, if any")
var subprinRule = "(forall P: forall Hash: TrustedProgramHash(Hash) and Subprin(P, %v, Hash) implies MemberProgram(P))"
var argsRule = "(forall Y: forall P: forall S: MemberProgram(P) and TrustedArgs(S) and Subprin(Y, P, S) implies Authorized(Y, \"Execute\"))"
var demoRule = "TrustedArgs(ext.Args(%s))"

func doClient(domain *tao.Domain) {
	// keys, err := tao.NewTemporaryTaoDelegatedKeys(tao.Signing, tao.Parent())
	// cert, err := keys.SigningKey.CreateSelfSignedX509(&pkix.Name{
	//	Organization: []string{"Google Tao Demo"}})
	//keys.Cert = cert
	// g := domain.Guard
}

// jlmtest

func JlmTest() error {
	if tao.Parent() != nil {
		fmt.Printf("I have a host\n")
	} else {
		fmt.Printf("I have no host\n")
	}
	name, err := tao.Parent().GetTaoName()
	if err != nil {
		return err
	}
	fmt.Printf("My root name is %s\n", name)

	var args []auth.Term
	for _, arg := range os.Args {
		args = append(args, auth.Str(arg))
	}

	e := auth.PrinExt{Name: "Args", Arg: args}
	err = tao.Parent().ExtendTaoName(auth.SubPrin{e})
	if err != nil {
		return err
	}

	name, err = tao.Parent().GetTaoName()
	if err != nil {
		return err
	}
	fmt.Printf("My full name is %s\n", name)

	random, err := tao.Parent().GetRandomBytes(10)
	if err != nil {
		return err
	}
	fmt.Printf("Random bytes  : % x\n", random)

	n, err := tao.Parent().Rand().Read(random)
	if err != nil {
		return err
	}
	fmt.Printf("%d more bytes : % x\n", n, random)

	secret, err := tao.Parent().GetSharedSecret(10, tao.SharedSecretPolicyDefault)
	if err != nil {
		return err
	}
	fmt.Printf("Shared secret : % x\n", secret)

	sealed, err := tao.Parent().Seal(random, tao.SealPolicyDefault)
	if err != nil {
		return err
	}
	fmt.Printf("Sealed bytes  : % x\n", sealed)

	unsealed, policy, err := tao.Parent().Unseal(sealed)
	if err != nil {
		return err
	}
	if policy != tao.SealPolicyDefault {
		return errors.New("unexpected policy on unseal")
	}
	fmt.Printf("Unsealed bytes: % x\n", unsealed)

	// var childSubprin auth.Prin
	// childSubprin= auth.SubPrin{auth.PrinExt{Name: "TestChild"}}
	attest, err := tao.Parent().Attest(nil, nil, nil, auth.Const(true))
	if err == nil {
		statement := proto.CompactTextString(attest)
		fmt.Printf("Attest worked\n%s\n", statement)
	} else {
		fmt.Printf("Attest failed\n")
	}

	return nil
}

func main() {
	flag.Parse()
	if tao.Parent() == nil {
		fmt.Printf("can't continue: No host Tao available\n")
		return
	}

	err := JlmTest()
	if err != nil {
		fmt.Printf("error from Jlmtest: %s\n", err.Error())
	}
	fmt.Printf("Done\n")
}
