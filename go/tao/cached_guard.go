// Copyright (c) 2015, Google Inc.  All rights reserved.
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
	"fmt"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
)

// CachedGuard implements the Guard interface on behalf of a remote guard.
// When the interface is queried, the cached guard checks if it has an
// up-to-date version of the policy. If it doesn't, it creates a connection
// to a TaoCA, requests the policy rules, and instantiates a new guard.
type CachedGuard struct {
	guardType CachedGuardType
	guard     Guard

	// Details of TaoCA, e.g. "tcp", "localhost:8124"
	network, address string

	// Public policy key. (The TaoCA should sign with the private policy key.)
	verifier *Verifier
}

// CachedGuardType specifies the type of guard being cached.
type CachedGuardType int

// There should be a type for all non-trivial gaurds.
const (
	Datalog CachedGuardType = 1 << iota
	ACLs
)

var errCachedGuardModify = errors.New("CachedGuard: modifying cached policy is not allowed.")
var errCachedGuardSave = errors.New("CachedGuard: saving cached policy is not allowed.")
var errCachedGuardReload = errors.New("CachedGuard: failed to update policy.")

// NewCachedGuard returns a new CachedGuard.
func NewCachedGuard(vfy *Verifier, t CachedGuardType, network, addr string) *CachedGuard {
	return &CachedGuard{
		guardType: t,
		network:   network,
		address:   addr,
		verifier:  vfy,
	}
}

// IsExpired checks if the cached policy is out of date.
func (cg *CachedGuard) IsExpired() bool {
	// TODO(cjpatton)
	return false
}

// Reload requests the policy from the remote TaoCA and instantiates a
// new guard.
func (cg *CachedGuard) Reload() error {
	switch cg.guardType {
	case Datalog:
		datalogGuard := NewDatalogGuard(cg.verifier)
		db, err := RequestDatalogRules(cg.network, cg.address, cg.verifier)
		if err != nil {
			return err
		}
		datalogGuard.db = *db
		for _, marshaledForm := range db.Rules {
			f, _ := auth.UnmarshalForm(marshaledForm)
			rule, _, err := datalogGuard.findRule(f)
			if err != nil {
				return err
			}
			datalogGuard.dl.Assert(rule)
		}
		// TODO(cjpatton) Set datalogGuard.modTime.
		cg.guard = datalogGuard
	case ACLs:
		// TODO(cjpatton)
	}
	return nil
}

// Subprincipal returns a Subprin for the guard.
func (cg *CachedGuard) Subprincipal() auth.SubPrin {
	// TODO(cjpatton) should be "CachedGuard(Datalog).DatalogGuard(...)"
	var guardType string
	switch cg.guardType {
	case Datalog:
		guardType = "Datalog"
	case ACLs:
		guardType = "ACLs"
	}
	e := auth.PrinExt{Name: "CachedGuard",
		Arg: []auth.Term{auth.Str(guardType)}}
	return auth.SubPrin{e}
}

// Save stores the cached policy to disk.
func (cg *CachedGuard) Save(key *Signer) error {
	// TODO(cjpatton) Save cached policy to disk (just call guard.Save()).
	// Add rules file to domain config. We will need a ReloadFromDisk()
	// method as well.
	return nil
}

// Authorize is not allowed for cached guards, since it doesn't have the
// private policy key.
func (cg *CachedGuard) Authorize(name auth.Prin, op string, args []string) error {
	return errCachedGuardModify
}

// Retract is not allowed for cached guards.
func (cg *CachedGuard) Retract(name auth.Prin, op string, args []string) error {
	return errCachedGuardModify
}

// IsAuthorized checks if the principal `name` is authorized to perform `op`
// on `args`.
func (cg *CachedGuard) IsAuthorized(name auth.Prin, op string, args []string) bool {
	if cg.guard == nil || cg.IsExpired() {
		if err := cg.Reload(); err != nil {
			return false
		}
	}
	return cg.guard.IsAuthorized(name, op, args)
}

// AddRule is not allowed for cached guards.
func (cg *CachedGuard) AddRule(rule string) error {
	return errCachedGuardModify
}

// RetractRule is not allowed for cached guards.
func (cg *CachedGuard) RetractRule(rule string) error {
	return errCachedGuardModify
}

// Clear deletes the guard. This will cause a Reload() the next time the guard
// is queried.
func (cg *CachedGuard) Clear() error {
	cg.guard = nil
	return nil
}

// Query the policy.
func (cg *CachedGuard) Query(query string) (bool, error) {
	if cg.guard == nil || cg.IsExpired() {
		if err := cg.Reload(); err != nil {
			return false, nil
		}
	}
	return cg.guard.Query(query)
}

// RuleCount returns the number of rules in the policy.
func (cg *CachedGuard) RuleCount() int {
	if cg.guard == nil || cg.IsExpired() {
		if err := cg.Reload(); err != nil {
			return 0
		}
	}
	return cg.guard.RuleCount()
}

// GetRule returns a string representation of the i-th rule in the policy.
func (cg *CachedGuard) GetRule(i int) string {
	if cg.guard == nil || cg.IsExpired() {
		if err := cg.Reload(); err != nil {
			return ""
		}
	}
	return cg.guard.GetRule(i)
}

// RuleDebugString returns a verbose string representation of the i-th rule
// in the policy useful for debugging.
func (cg *CachedGuard) RuleDebugString(i int) string {
	if cg.guard == nil || cg.IsExpired() {
		if err := cg.Reload(); err != nil {
			return ""
		}
	}
	return cg.guard.RuleDebugString(i)
}

// String returns a string representation of the guard.
func (cg *CachedGuard) String() string {
	var s string
	if cg.guard == nil {
		switch cg.guardType {
		case Datalog:
			s = fmt.Sprintf("undefined Datalog, %s", cg.address)
		case ACLs:
			s = fmt.Sprintf("undefined ACLs, %s", cg.address)
		}
	} else {
		s = "\n" + cg.guard.String() + "\n"
	}
	return "CachedGuard{" + s + "}"
}
