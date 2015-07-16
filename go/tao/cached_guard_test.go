// Copyright (c) 2015, Google Inc. All rights reserved.
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

package tao

import (
	"fmt"
	"net"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
)

// TODO(cjpatton) Add a test case to show it fails properly when the rules
// can't be loaded, e.g. when there is no network config.
// TODO(cjaptton) Use t.Error() to log errors instead of t.Fatal() in the case
// that a recoverable error occured.
// TODO(cjpatton) Write request to poll every few seconds until a connection is
// established,
// TODO(cjpatton) Modify CreatePublicCachedDomain() to accept either (network,addr) or a
// net.Conn. Modify this test to use net.Pipe instead of the loopback interface here.

func TestCachingDatalogReload(t *testing.T) {
	network := "tcp"
	addr := "localhost:8124"

	// Create a domain with a Datalog guard and policy keys.
	var policyDomainConfig DomainConfig
	policyDomainConfig.SetDefaults()
	policyDomainConfig.DomainInfo.GuardType = proto.String("Datalog")
	policyDomainConfig.DatalogGuardInfo = &DatalogGuardDetails{
		SignedRulesPath: proto.String("rules"),
	}
	configPath := "/tmp/domain_test/tao.config"
	password := make([]byte, 32)

	policyDomain, err := CreateDomain(policyDomainConfig, configPath, password)
	if err != nil {
		t.Fatal(err)
	}

	// Add some bogus rules.
	prin := auth.NewKeyPrin([]byte("Alice"))
	err = policyDomain.Guard.AddRule(fmt.Sprintf(
		`(forall P: forall F: IsFood(F) and IsPerson(P) implies Authorized(P, "eat", F))`))
	if err != nil {
		t.Fatal(err)
	}
	if err = policyDomain.Guard.AddRule(fmt.Sprintf(`IsPerson(%s)`, prin)); err != nil {
		t.Fatal(err)
	}
	if err = policyDomain.Guard.AddRule(fmt.Sprintf(`IsFood("sandwich")`)); err != nil {
		t.Fatal(err)
	}

	// Sanity check.
	if policyDomain.Guard.IsAuthorized(prin, "eat", []string{"sandwich"}) == false {
		t.Fatal("denied, should have been authorized")
	}

	// Run the TaoCA. This handles one request and then exits.
	ch := make(chan bool)
	cal, err := net.Listen(network, addr)
	if err != nil {
		t.Fatal(err)
	}
	go runTCCA(t, cal, policyDomain.Keys, policyDomain.Guard, ch)

	// Create a public domain with a Cached Datalog guard.
	publicDomain, err := policyDomain.CreatePublicCachedDomain(network, addr)
	if err != nil {
		t.Fatal(err)
	}

	// Generate policy request.
	if err = publicDomain.Guard.(*CachedGuard).Reload(); err != nil {
		t.Fatal(err)
	}

	// Print rules.
	ct := publicDomain.Guard.RuleCount()
	for i := 0; i < ct; i++ {
		t.Logf("rule %d: %s", i, publicDomain.Guard.GetRule(i))
	}

	// Try a query.
	if publicDomain.Guard.IsAuthorized(prin, "eat", []string{"sandwich"}) == false {
		t.Fatal("denied, should have been authorized")
	}

	if publicDomain.Guard.IsAuthorized(prin, "eat", []string{"salad"}) == true {
		t.Fatal("authorized, should have been denied")
	}
	<-ch
}
