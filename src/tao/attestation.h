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

#include <string>

#include "tao/attestation.pb.h"

using std::string;

namespace tao {

/// Generate a signed key-to-name binding attestation.
/// @param key The signing key, i.e. the principal attesting to this binding.
/// @param delegation A serialized Attestation to provide evidence that the
/// signing key speaks for the name being bound, or evidence if no evidence is
/// needed (i.e. if the name is a equal to or a subprincipal of the signing
/// key).
/// @param key_prin The key being bound, serialized in PEM format.
/// @param name The name to which the key is being bound.
/// @param[out] attestation The signed attestation.
/// Note: Reasonable default values will be chosen for the expiration and
/// timestamp.
bool AttestKeyNameBinding(const Keys &key, const string &delegation,
                          const string &key_prin, const string &name,
                          string *attestation);

/// Extract the name part of a key-to-name binding attestation.
/// @param attestation The attestation, which is assumed to be valid (no
/// signature or structural checks are done).
/// @param[out] name The name part of the binding.
bool GetNameFromKeyNameBinding(const string &attestation, string *name);

/// Extract the key part of a key-to-name binding attestation.
/// @param attestation The attestation, which is assumed to be valid (no
/// signature or structural checks are done).
/// @param[out] key_prin The key part of the binding.
bool GetKeyFromKeyNameBinding(const string &attestation, string *key_prin);

/// Validate a signed key-to-name binding attestation.
/// @param attestation The attestation to be checked.
/// @param check_time A timestamp to use for checking time restrictions.
/// @param[out] key_prin The key part of the binding.
/// @param[out] name The name part of the binding.
bool ValidateKeyNameBinding(const string &attestation, time_t check_time,
                            string *key_prin, string *name);

/// Generate a pretty-printed representation of an Attestation.
/// @param a The attestation to pretty-print.
string DebugString(const Attestation &a);

/// Generate a pretty-printed representation of a Statement.
/// @param s The statement to pretty-print.
string DebugString(const Statement &s);

}  // namespace tao

#endif  // TAO_ATTESTATION_H_
