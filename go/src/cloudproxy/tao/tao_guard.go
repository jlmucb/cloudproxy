// Copyright (c) 2013, Google Inc.  All rights reserved.
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

// This interface was derived from the code in src/tao/tao_guard.h.

package tao

import (
	"errors"

	"cloudproxy/tao/auth"
)

// MakePredicate constructs an authorization predicate of the form:
//   Authorize(name, op, args...).
// TODO(tmroeder): implement this function.
func MakePredicate(name auth.Prin, op string, args []string) string {
	return ""
}

// A TaoGuard is an interface for evaluating policy decisions.
type TaoGuard interface {
	// Subprincipal returns a unique subprincipal for this policy.
	Subprincipal() auth.SubPrin

	// Save writes all presistent policy data to disk, signed by key.
	Save(key *Signer) error

	// Authorize adds an authorization for a principal to perform an
	// operation.
	Authorize(name auth.Prin, op string, args []string) error

	// Retract removes an authorization for a principal to perform an
	// operation, essentially reversing the effect of an Authorize() call
	// with identical name, op, and args. Note: this reverses the effect of
	// an Authorize() call with identical parameters of the equivalent
	// AddRule() call. However, particularly when expressive policies are
	// supported (e.g., an "authorize all" rule), other rules may still be
	// in place authorizing the principal to perform the operation.
	Retract(name auth.Prin, op string, args []string) error

	// IsAuthorized checks whether a principal is authorized to perform an
	// operation.
	IsAuthorized(name auth.Prin, op string, args []string) bool

	// AddRule adds a policy rule. Subclasses should support at least rules
	// of the form: Authorized(P, op, args...). This is equivalent to
	// calling Authorize(P, op, args...) with each of the arguments
	// converted to either a string or integer.
	AddRule(rule string) error

	// RetractRule removes a rule previously added via AddRule() or the
	// equivalent Authorize() call.
	RetractRule(rule string) error

	// Clear removes all rules.
	Clear() error

	// Query the policy. Implementations of this interface should support
	// at least queries of the form: Authorized(P, op, args...).
	Query(query string) (bool, error)

	// RuleCount returns a count of the total number of rules.
	RuleCount() int

	// GetRule returns the ith policy rule, if it exists.
	GetRule(i int) string

	// RuleDebugString returns a debug string for the ith policy rule, if
	// it exists.
	RuleDebugString(i int) string

	// String returns a string suitable for showing users authorization
	// info.
	String() string
}

// A TrivialGuard implements a constant policy: either ConservativeGuard ("deny
// all") or LiberalGuard ("allow all").
// TODO(kwalsh) make this a bool
type TrivialGuard int

// The types of TrivialGuard
const (
	ConservativeGuard TrivialGuard = 1 << iota
	LiberalGuard
)

// errTrivialGuard is the error returned for all non-trivial policy operations
// on the TrivialGuard.
var errTrivialGuard = errors.New("can't perform policy operations on TrivialGuard")

// SubprincipalName returns subprincipal TrivialGuard(<policy>).
func (t TrivialGuard) Subprincipal() auth.SubPrin {
	var policy string
	switch t {
	case ConservativeGuard:
		policy = "Conservative"
	case LiberalGuard:
		policy = "Liberal"
	default:
		policy = "Unspecified"
	}
	e := auth.PrinExt{Name: "TrivialGuard", Arg:[]auth.Term{auth.Str(policy)}}
	return auth.SubPrin{e}
}

// Save writes all presistent policy data to disk, signed by key.
func (t TrivialGuard) Save(key *Signer) error {
	return nil // nothing to save
}

// Authorize adds an authorization for a principal to perform an
// operation.
func (t TrivialGuard) Authorize(name auth.Prin, op string, args []string) error {
	return errTrivialGuard
}

// Retract removes an authorization for a principal to perform an
// operation, essentially reversing the effect of an Authorize() call
// with identical name, op, and args. Note: this reverses the effect of
// an Authorize() call with identical parameters of the equivalent
// AddRule() call. However, particularly when expressive policies are
// supported (e.g., an "authorize all" rule), other rules may still be
// in place authorizing the principal to perform the operation.
func (t TrivialGuard) Retract(name auth.Prin, op string, args []string) error {
	return errTrivialGuard
}

// IsAuthorized checks whether a principal is authorized to perform an
// operation.
func (t TrivialGuard) IsAuthorized(name auth.Prin, op string, args []string) bool {
	switch t {
	case ConservativeGuard:
		return false
	case LiberalGuard:
		return true
	default:
		return false
	}
}

// AddRule adds a policy rule. Subclasses should support at least rules
// of the form: Authorized(P, op, args...). This is equivalent to
// calling Authorize(P, op, args...) with each of the arguments
// converted to either a string or integer.
func (t TrivialGuard) AddRule(rule string) error {
	return errTrivialGuard
}

// RetractRule removes a rule previously added via AddRule() or the
// equivalent Authorize() call.
func (t TrivialGuard) RetractRule(rule string) error {
	return errTrivialGuard
}

// Clear removes all rules.
func (t TrivialGuard) Clear() error {
	return errTrivialGuard
}

// Query the policy. Implementations of this interface should support
// at least queries of the form: Authorized(P, op, args...).
func (t TrivialGuard) Query(query string) (bool, error) {
	switch t {
	case ConservativeGuard:
		return false, nil
	case LiberalGuard:
		return true, nil
	default:
		return false, nil
	}
}

// RuleCount returns a count of the total number of rules.
func (t TrivialGuard) RuleCount() int {
	return 1
}

// GetRule returns the ith policy rule, if it exists.
func (t TrivialGuard) GetRule(i int) string {
	switch t {
	case ConservativeGuard:
		return "Deny All"
	case LiberalGuard:
		return "Allow All"
	default:
		return "Unspecified Policy"
	}
}

// RuleDebugString returns a debug string for the ith policy rule, if
// it exists.
// TODO(kwalsh): build this into the auth library.
func (t TrivialGuard) RuleDebugString(i int) string {
	switch t {
	case ConservativeGuard:
		return "Deny All"
	case LiberalGuard:
		return "Allow All"
	default:
		return "Unspecified Policy"
	}
}

// String returns a string suitable for showing users authorization info.
func (t TrivialGuard) String() string {
	switch t {
	case ConservativeGuard:
		return "Trivial Conservative Policy (a.k.a. \"deny all\")"
	case LiberalGuard:
		return "Trivial Liberal Policy (a.k.a. \"allow all\")"
	default:
		return "Unspecified Policy"
	}
}
