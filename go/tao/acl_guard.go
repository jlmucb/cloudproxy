// Copyright (c) 2014, Google Inc.  All rights reserved.
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
	"errors"
	"io/ioutil"
	"os"
	"strings"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
)

// An ACLGuard is an implementation of tao.Guard that uses an ACL to make
// authorization decisions. All rules are immediately converted to strings when
// they are added, and they are never converted back to auth.ast form. Any
// policy that requires more than string comparison should use DatalogGuard.
type ACLGuard struct {
	Config ACLGuardDetails
	ACL    []string
	Key    *Verifier
}

// ACLGuardSigningContext is the context used for ACL-file signatures.
const ACLGuardSigningContext = "tao.ACLGuard Version 1"
const aclGuardFileMode os.FileMode = 0600

// NewACLGuard produces a Guard implementation that implements ACLGuard.
func NewACLGuard(key *Verifier, config ACLGuardDetails) Guard {
	return &ACLGuard{Config: config, Key: key}
}

// Subprincipal returns a unique subprincipal for this policy.
func (a *ACLGuard) Subprincipal() auth.SubPrin {
	if a.Key == nil {
		e := auth.PrinExt{Name: "ACLGuard"}
		return auth.SubPrin{e}
	} else {
		e := auth.PrinExt{Name: "ACLGuard", Arg: []auth.Term{a.Key.ToPrincipal()}}
		return auth.SubPrin{e}
	}
}

// Save writes all presistent policy data to disk, signed by key.
func (a *ACLGuard) Save(key *Signer) error {
	acls := &ACLSet{Entries: a.ACL}
	ser, err := proto.Marshal(acls)
	if err != nil {
		return err
	}

	sig, err := key.Sign(ser, ACLGuardSigningContext)
	if err != nil {
		return err
	}
	signedACL := &SignedACLSet{
		SerializedAclset: ser,
		Signature:        sig,
	}

	b, err := proto.Marshal(signedACL)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(a.Config.GetSignedAclsPath(), b, aclGuardFileMode); err != nil {
		return err
	}

	return nil
}

// Load restores a set of rules saved with Save. It replaces any rules in the
// ACLGuard with the rules it loaded. In the process, it also checks the
// signature created during the Save process.
func LoadACLGuard(key *Verifier, config ACLGuardDetails) (Guard, error) {
	b, err := ioutil.ReadFile(config.GetSignedAclsPath())
	if err != nil {
		return nil, err
	}

	var sigACL SignedACLSet
	if err := proto.Unmarshal(b, &sigACL); err != nil {
		return nil, err
	}

	ok, err := key.Verify(sigACL.SerializedAclset, ACLGuardSigningContext, sigACL.Signature)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, errors.New("the signature on the file didn't pass verification")
	}

	var acls ACLSet
	if err := proto.Unmarshal(sigACL.SerializedAclset, &acls); err != nil {
		return nil, err
	}
	a := &ACLGuard{Config: config, Key: key}
	a.ACL = acls.Entries
	return a, nil
}

func createPredicateString(name auth.Prin, op string, args []string) string {
	p := auth.Pred{
		Name: "Authorized",
		Arg:  make([]auth.Term, len(args)+2),
	}
	p.Arg[0] = name
	p.Arg[1] = auth.Str(op)
	for i, s := range args {
		p.Arg[i+2] = auth.Str(s)
	}

	return p.String()
}

// Authorize adds an authorization for a principal to perform an
// operation.
func (a *ACLGuard) Authorize(name auth.Prin, op string, args []string) error {
	a.ACL = append(a.ACL, createPredicateString(name, op, args))
	return nil
}

// Retract removes an authorization for a principal to perform an
// operation, essentially reversing the effect of an Authorize() call
// with identical name, op, and args. Note: this reverses the effect of
// an Authorize() call with identical parameters of the equivalent
// AddRule() call. However, particularly when expressive policies are
// supported (e.g., an "authorize all" rule), other rules may still be
// in place authorizing the principal to perform the operation.
func (a *ACLGuard) Retract(name auth.Prin, op string, args []string) error {
	ps := createPredicateString(name, op, args)
	i := 0
	for i < len(a.ACL) {
		if ps == a.ACL[i] {
			a.ACL[i], a.ACL, i = a.ACL[len(a.ACL)-1], a.ACL[:len(a.ACL)-1], i-1
		}

		i++
	}
	return nil
}

// IsAuthorized checks whether a principal is authorized to perform an
// operation.
func (a *ACLGuard) IsAuthorized(name auth.Prin, op string, args []string) bool {
	ps := createPredicateString(name, op, args)
	for _, s := range a.ACL {
		if s == ps {
			return true
		}
	}
	return false
}

// AddRule adds a policy rule. Subclasses should support at least rules
// of the form: Authorized(P, op, args...). This is equivalent to
// calling Authorize(P, op, args...) with each of the arguments
// converted to either a string or integer.
func (a *ACLGuard) AddRule(rule string) error {
	glog.Infof("Adding rule '%s'", rule)
	a.ACL = append(a.ACL, rule)
	return nil
}

// RetractRule removes a rule previously added via AddRule() or the
// equivalent Authorize() call.
func (a *ACLGuard) RetractRule(rule string) error {
	i := 0
	for i < len(a.ACL) {
		if rule == a.ACL[i] {
			a.ACL[i], a.ACL, i = a.ACL[len(a.ACL)-1], a.ACL[:len(a.ACL)-1], i-1
		}

		i++
	}
	return nil
}

// Clear removes all rules.
func (a *ACLGuard) Clear() error {
	a.ACL = make([]string, 0)
	return nil
}

// Query the policy. Implementations of this interface should support
// at least queries of the form: Authorized(P, op, args...).
func (a *ACLGuard) Query(query string) (bool, error) {
	for _, s := range a.ACL {
		if query == s {
			return true, nil
		}
	}

	return false, nil
}

// RuleCount returns a count of the total number of rules.
func (a *ACLGuard) RuleCount() int {
	return len(a.ACL)
}

// GetRule returns the ith policy rule, if it exists.
func (a *ACLGuard) GetRule(i int) string {
	if i >= len(a.ACL) || i < 0 {
		return ""
	}
	return a.ACL[i]
}

// RuleDebugString returns a debug string for the ith policy rule, if
// it exists.
func (a *ACLGuard) RuleDebugString(i int) string {
	return a.GetRule(i)
}

// String returns a string suitable for showing users authorization
// info.
func (a *ACLGuard) String() string {
	return "ACLGuard{\n" + strings.Join(a.ACL, "\n") + "\n}"
}
