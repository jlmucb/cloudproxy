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
	"os"
	"path"
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

var password []byte = make([]byte, 32)
var prin auth.Prin = auth.NewKeyPrin([]byte("Alice"))

func makeTestDomains(configDir, network, addr string, ttl int64) (policy *Domain, public *Domain, err error) {

	// Create a domain with a Datalog guard and policy keys.
	var policyDomainConfig DomainConfig
	policyDomainConfig.SetDefaults()
	policyDomainConfig.DomainInfo.GuardType = proto.String("Datalog")
	policyDomainConfig.DatalogGuardInfo = &DatalogGuardDetails{
		SignedRulesPath: proto.String("rules"),
	}
	configPath := path.Join(configDir, "tao.config")

	policy, err = CreateDomain(policyDomainConfig, configPath, password)
	if err != nil {
		return nil, nil, err
	}

	// Add some bogus rules.
	err = policy.Guard.AddRule(
		`(forall P: forall F: IsFood(F) and IsPerson(P) implies Authorized(P, "eat", F))`)
	if err != nil {
		return nil, nil, err
	}
	if err = policy.Guard.AddRule(fmt.Sprintf(`IsPerson(%s)`, prin)); err != nil {
		return nil, nil, err
	}
	if err = policy.Guard.AddRule(`IsFood("sandwich")`); err != nil {
		return nil, nil, err
	}

	// Create a public domain with a Cached Datalog guard.
	public, err = policy.CreatePublicCachedDomain(network, addr, ttl)
	if err != nil {
		return nil, nil, err
	}

	return
}

func TestCachingDatalogLoad(t *testing.T) {
	var network, addr string
	var ttl int64
	network = "tcp"
	addr = "localhost:8124"
	ttl = 1
	configDir := "/tmp/domain_test"

	policy, _, err := makeTestDomains(configDir, network, addr, ttl)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(configDir)
	defer os.RemoveAll(configDir + ".pub")

	public, err := LoadDomain(path.Join(configDir+".pub", "tao.config"), nil)
	if err != nil {
		t.Fatal(err)
	}

	ch := make(chan bool)
	cal, err := net.Listen(network, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer cal.Close()
	go runTCCA(t, cal, policy.Keys, policy.Guard, ch)

	// This should cause an implicit reload. If the request to the TaoCA fails,
	// IsAuthorized() will return false and not propagate an error.
	if public.Guard.IsAuthorized(prin, "eat", []string{"sandwich"}) == false {
		t.Fatal("IsAuthorized() failed, good rule should have been authorized")
	}
	<-ch
}

func TestCachingDatalogReload(t *testing.T) {

	var network, addr string
	var ttl int64
	network = "tcp"
	addr = "localhost:8124"
	ttl = 10

	configDir := "/tmp/domain_test"
	policyDomain, publicDomain, err := makeTestDomains(configDir, network, addr, ttl)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(configDir)
	defer os.RemoveAll(configDir + ".pub")

	// Sanity check.
	if policyDomain.Guard.IsAuthorized(prin, "eat", []string{"sandwich"}) == false {
		t.Fatal("Policy guard IsAuthorized() failed, good rule should have been authorized")
	}

	// Run the TaoCA. This handles one request and then exits.
	ch := make(chan bool)
	cal, err := net.Listen(network, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer cal.Close()
	go runTCCA(t, cal, policyDomain.Keys, policyDomain.Guard, ch)

	// Explicitly call Reload(), generating a policy request.
	if err = publicDomain.Guard.(*CachedGuard).Reload(); err != nil {
		t.Fatal(err)
	}

	// Print rules.
	ct := publicDomain.Guard.RuleCount()
	for i := 0; i < ct; i++ {
		t.Logf("rule %d: %s", i, publicDomain.Guard.GetRule(i))
	}
	<-ch

	// Force Reload() by clearing the guard.
	publicDomain.Guard.Clear()
	go runTCCA(t, cal, policyDomain.Keys, policyDomain.Guard, ch)

	// This should cause an implicit reload. If the request to the TaoCA fails,
	// IsAuthorized() will return false and not propagate an error.
	if publicDomain.Guard.IsAuthorized(prin, "eat", []string{"sandwich"}) == false {
		t.Fatal("IsAuthorized() failed, good rule should have been authorized")
	}
	<-ch

	// Simulate time-to-live running out.
	publicDomain.Guard.(*CachedGuard).timeUpdated -= ttl + 1
	go runTCCA(t, cal, policyDomain.Keys, policyDomain.Guard, ch)

	if publicDomain.Guard.IsAuthorized(prin, "eat", []string{"salad"}) == true {
		t.Fatal("IsAuthorized() succeeded, bad rule should have been denied")
	}
	<-ch
}
