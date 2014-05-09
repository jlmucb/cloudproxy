//  File: attestation.h
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Attestation utilities.
//
//  Copyright (c) 2014, Kevin Walsh.  All rights reserved.
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
#ifndef TAO_ATTESTATION_H_
#define TAO_ATTESTATION_H_

#include <list>
#include <string>

#include "tao/attestation.pb.h"

namespace tao {
using std::list;
using std::string;

class Keys;

/// Utilities for arbitrary attestations.
/// @{

/// Generate a signed attestation.
/// @param key The signing key.
/// @param delegation A serialized delegation attestation to provide evidence
/// that the signing key speaks for the issuer, or emptystring if no such
/// evidence is needed.
/// @param s The Statement to be signed.
/// @param[out] attestation The signed attestation.
bool GenerateAttestation(const Keys &key, const string &delegation,
                         const Statement &s, string *attestation);

/// Validate a signed attestation.
/// @param attestation The attestation to be checked.
/// @param[out] issuer The issuer from the attestation statement.
/// @param[out] stmt The statement conveyed by this attestation.
/// Note: The time and expiration in the returned statement will
/// be adjusted appropriately if there are embedded delegations.
bool ValidateAttestation(const string &attestation, Statement *stmt);

/// Extract the issuer part of an attestation, without verifying it.
/// @param attestation The attestation, which is assumed to be valid (no
/// signature or structural checks are done).
/// @param[out] name The issuer part of the statement within the attestation.
bool GetAttestationIssuer(const string &attestation, string *issuer);

/// Get the current time as a POSIX 64-bit time.
time_t CurrentTime();

/// Generate a pretty-printed representation of an Attestation.
/// @param a The attestation to pretty-print.
string DebugString(const Attestation &a);

/// Generate a pretty-printed representation of a Statement.
/// @param s The statement to pretty-print.
string DebugString(const Statement &s);

/// @}

/// Utilities for delegation attestations.
/// @{

/// Generate a delegation attestation.
/// @param key The signing key.
/// @param delegation A serialized delegation attestation to provide evidence
/// that the signing key speaks for the issuer, or emptystring if no such
/// evidence is needed.
/// @param delegate The identity of the delegate.
/// @param issuer The identity of the issuer.
/// @param[out] attestation The signed attestation.
/// Note: Reasonable default values will be chosen for the expiration and
/// timestamp.
bool AttestDelegation(const Keys &key, const string &delegation,
                      const string &delegate, const string &issuer,
                      string *attestation);

/// Validate a delegation attestation.
/// @param attestation The attestation to be checked.
/// @param check_time A timestamp to use for checking time restrictions.
/// @param[out] delegate The delegate from the attestation statement.
/// @param[out] issuer The issuer from the attestation statement.
bool ValidateDelegation(const string &attestation, time_t check_time,
                        string *delegate, string *issuer);

/// Extract the delegate part of a delegation attestation without verifying it.
/// @param attestation A delegation attestation, which is assumed to be valid
/// (no signature or structural checks are done).
/// @param[out] name The delegate part of the statement within the attestation.
bool GetAttestationDelegate(const string &attestation, string *delegate);

/// @}

/// Utilities for predicate attestations.
/// @{

/// Generate a predicate attestation.
/// @param key The signing key.
/// @param delegation A serialized delegation attestation to provide evidence
/// that the signing key speaks for the issuer, or emptystring if no such
/// evidence is needed.
/// @param issuer The identity of the issuer.
/// @param predicate A simple name to use as the predicate.
/// @param args A list of arguments to the predicate.
/// @param[out] attestation The signed attestation.
/// Note: Reasonable default values will be chosen for the expiration and
/// timestamp.
bool AttestPredicate(const Keys &key, const string &delegation,
                     const string &issuer, const string &predicate,
                     const list<string> &args, string *attestation);

/// Validate a predicate attestation.
/// @param attestation The attestation to be checked.
/// @param check_time A timestamp to use for checking time restrictions.
/// @param[out] issuer The issuer from the attestation statement.
/// @param[out] predicate The predicate name from the attestation statement.
/// @param[out] predicate The list of predicate arguments from the attestation
/// statement.
bool ValidatePredicate(const string &attestation, time_t check_time,
                       string *issuer, string *predicate, list<string> *args);

/// Extract the predicate name and arguments from a predicate attestation,
/// without verifying it..
/// @param attestation The attestation, which is assumed to be valid (no
/// signature or structural checks are done).
/// @param[out] predicate The predicate name from the attestation.
/// @param[out] args The list of predicate arguments from the attestation.
bool GetAttestationPredicate(const string &attestation, string *predicate,
                             list<string> *args);

/// @}

}  // namespace tao

#endif  // TAO_ATTESTATION_H_
