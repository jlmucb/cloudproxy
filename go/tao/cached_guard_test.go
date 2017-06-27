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
	"crypto/x509/pkix"
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

var password = make([]byte, 32)
var prin = auth.NewKeyPrin([]byte("Alice"))

func makeTestDomains(configDir, network, addr string, ttl int64) (policy *Domain, public *Domain, err error) {
	password[0] = 1

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
	if err = policy.Guard.AddRule(fmt.Sprintf(`IsPerson(%v)`, prin)); err != nil {
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
	network := "tcp"
	addr := "localhost:0"
	ttl := int64(1)
	configDir := "/tmp/domain_test"

	ch := make(chan bool)
	cal, err := net.Listen(network, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer cal.Close()
	addr = cal.Addr().String()

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

	go runTCCA(t, cal, policy.Keys, policy.Guard, ch)

	// This should cause an implicit reload. If the request to the TaoCA fails,
	// IsAuthorized() will return false and not propagate an error.
	if public.Guard.IsAuthorized(prin, "eat", []string{"sandwich"}) == false {
		t.Fatal("IsAuthorized() failed, good rule should have been authorized")
	}
	<-ch
}

func TestCachingDatalogReload(t *testing.T) {

	network := "tcp"
	addr := "localhost:0"
	ttl := int64(10)

	// Run the TaoCA. This handles one request and then exits.
	ch := make(chan bool)
	cal, err := net.Listen(network, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer cal.Close()
	addr = cal.Addr().String()

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

// Test that a client can correctly verify that the server is allowed to
// execute according to the policy. The policy is set up and the policy
// key is used to attest to the identity of the server. The attestation
// includes an endorsement of the service itself. The client verifies the
// endorsement and adds the predicate to the policy before checking it.
func TestCachingDatalogValidatePeerAttestation(t *testing.T) {
	network := "tcp"
	addr := "localhost:0"
	ttl := int64(1)
	tmpDir := "/tmp/domain_test"

	// Set up the TaoCA.
	ch := make(chan bool)
	cal, err := net.Listen(network, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer cal.Close()
	addr = cal.Addr().String()

	// Set up the policy domain and a public, cached version.
	policy, pub, err := makeTestDomains(tmpDir, network, addr, ttl)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)
	defer os.RemoveAll(tmpDir + ".pub")

	// Set up policy. A key being authorized to execute is of course nonsense;
	// this is only meant to test that ValidatePeerAttestation() properly adds
	// the endoresement to the policy.
	rule := "(forall K: TrustedKey(K) implies Authorized(K, \"Execute\"))"
	if err := policy.Guard.AddRule(rule); err != nil {
		t.Errorf("could not add rule : %s", err)
		return
	}

	// Generate a set of keys for the Tao-delegated server.
	k, err := NewTemporaryTaoDelegatedKeys(Signing|Crypting|Deriving, nil)
	if err != nil {
		t.Error("failed to generate keys:", err)
		return
	}
	k.dir = tmpDir

	// Generate an attesation of the statements: "k.VerifyingKey speaks for
	// key(K)" and "TrustedKey(key(K))" signed by the policy key and set to
	// k.Delegation.
	prin := auth.NewKeyPrin([]byte("This is a terrible key."))

	pred := auth.Pred{
		Name: "TrustedKey",
		Arg:  []auth.Term{prin},
	}

	sf := auth.Speaksfor{
		Delegate:  k.SigningKey.ToPrincipal(),
		Delegator: prin,
	}

	stmt := auth.Says{
		Speaker:    policy.Keys.SigningKey.ToPrincipal(),
		Time:       nil,
		Expiration: nil,
		Message:    sf,
	}

	if k.Delegation, err = GenerateAttestation(policy.Keys.SigningKey, nil, stmt); err != nil {
		t.Error("failed to attest to speaksfor:", err)
		return
	}

	e := auth.Says{
		Speaker: policy.Keys.SigningKey.ToPrincipal(),
		Message: pred,
	}

	ea, err := GenerateAttestation(policy.Keys.SigningKey, nil, e)
	if err != nil {
		t.Error("failed to attest to endorsement:", err)
		return
	}

	eab, err := proto.Marshal(ea)
	if err != nil {
		t.Error("failed to marshal attested endorsement:", err)
		return
	}
	k.Delegation.SerializedEndorsements = [][]byte{eab}

	// Generate an x509 certificate for the Tao-delegated server.
	signerAlg := SignerTypeFromSuiteName(TaoCryptoSuite)
	if signerAlg == nil {
		t.Error("Cant get signer alg from ciphersuite")
	}
	pkInt := PublicKeyAlgFromSignerAlg(*signerAlg)
	skInt := SignatureAlgFromSignerAlg(*signerAlg)
	if pkInt < 0 || skInt < 0 {
		t.Error("Cant get x509 signer alg from signer alg")
	}
	k.Cert, err = k.SigningKey.CreateSelfSignedX509(pkInt, skInt, 1,
		&pkix.Name{Organization: []string{"Identity of some Tao service"}})
	if err != nil {
		t.Error("failed to generate x509 certificate:", err)
		return
	}

	// Run the TaoCA. This handles one request and then exits.
	go runTCCA(t, cal, policy.Keys, policy.Guard, ch)

	// Add any verified predicates to the policy. This will cause a
	// policy query to the TaoCA.
	if err = AddEndorsements(pub.Guard, k.Delegation, pub.Keys.VerifyingKey); err != nil {
		t.Error("failed to add endorsements:", err)
		t.Errorf("pub verifier key is %v\n", pub.Keys.VerifyingKey.ToPrincipal())
		t.Errorf("policy ssigning key  is %v\n", policy.Keys.SigningKey.ToPrincipal())
		t.Errorf("k signing key is %v\n", k.SigningKey.ToPrincipal())
		return
	}

	<-ch

	// Finally, the client verifies the Tao-delegated server is allowed to
	// execute.
	if err = ValidatePeerAttestation(k.Delegation, k.Cert, pub.Guard); err != nil {
		t.Error("failed to verity attestation:", err)
	}
}
