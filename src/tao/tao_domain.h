//  File : tao_domain.h
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Administrative methods for the Tao.
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
#ifndef TAO_TAO_DOMAIN_H_
#define TAO_TAO_DOMAIN_H_

#include <list>
#include <string>

#include "tao/keys.h"
#include "tao/keys.pb.h"
#include "tao/tao_domain.pb.h"
#include "tao/tao_guard.h"
#include "tao/util.h"

namespace tao {
using std::string;

class Attestation;
class Keys;

/// A TaoDomain stores and manages a set of configuration parameters for a
/// single administrative domain, including a policy key pair, the host:port
/// location to access a Tao CA (if available). Classes that extend TaoDomain
/// also implement TaoGuard to govern authorization for the administrative
/// domain, and they store and manage any configuration necessary for that
/// purpose, e.g. the location of ACL files.
///
/// Except for a password used to encrypt the policy private key, all
/// configuration data for TaoDomain is stored in a text file, typically named
/// "tao.config". This configuration file contains the locations of all other
/// files and directories needed by TaoDomain. File and directory paths within
/// the tao.config file are relative to the location of the tao.config file
/// itself.
class TaoDomain : public TaoGuard {
 public:
  virtual ~TaoDomain();

  /// Initialize a new TaoDomain and write its configuration files to a
  /// directory. This creates the directory if needed, creates a policy key
  /// pair, and initializes default state for authorization, e.g. an empty
  /// set of ACLs.
  /// @param initial_config A string containing the initial configuration
  /// for this TaoDomain, using protobuf TextFormat for TaoDomainConfig.
  /// @param path The location to store the configuration file.
  /// @param password A password for encrypting the policy private key.
  static TaoDomain *Create(const string &initial_config, const string &path,
                           const string &password);

  /// Initialize a TaoDomain from an existing configuration file. The object
  /// will be "locked", meaning that the policy private signing key will not be
  /// available, new ACL entries or attestations can not be signed, etc.
  /// @param path The location of the existing configuration file.
  static TaoDomain *Load(const string &path) { return Load(path, ""); }

  /// Initialize a TaoDomain from an existing configuration file.
  /// @param path The location of the existing configuration file.
  /// @param password The password to unlock the policy private key. If password
  /// is emptystring, then the TaoDomain object will be "locked", meaning that
  /// the policy private signing key will not be available, new ACL entries or
  /// attestations can not be signed, etc.
  static TaoDomain *Load(const string &path, const string &password);

  /// Get the name of this administrative domain.
  string GetName() const { return config->name(); }

  /// Get the policy key signer. This returns nullptr if the object is locked.
  const Signer *GetPolicySigner() const { return keys_->Signer(); }

  /// Get the policy key verifier.
  const Verifier *GetPolicyVerifier() const { return keys_->Verifier(); }

  /// Get the policy keys.
  const Keys *GetPolicyKeys() const { return keys_.get(); }

  /// Create a key-to-name binding attestation, signed by the policy private
  /// key. If K_policy is the policy key, typical bindings are:
  ///     (i) K_aik binds to K_policy::TrustedPlatform
  ///         (a name that is trusted on certain tpm-related matters)
  ///    (ii) K_os binds to K_policy::TrustedOS
  ///         (a name that is trusted on certain OS-related matters)
  ///   (iii) K_app binds to K_policy::App("name")
  ///         (a name that is trusted to execute within this domain
  ///         and may also be trusted on certain other matters).
  /// The attestation's statement timestamp and expiration will be filled with
  /// reasonable values, i.e. the current time and a default expiration.
  /// @param key_prin A principal encoding the key to be bound.
  /// @param subprin The subprincipal part of the binding name.
  /// @param[out] attestation The signed attestation.
  // bool AttestKeyNameBinding(const string &key_prin, const string &subprin,
  //                          string *attestation) const;

  /// Authorize a program to execute with the given arguments. A pattern that
  /// matches the program's tentative name will be computed and added to the set
  /// of names authorized to execute.
  /// @param path The location of the program binary to be added.
  /// @param args A list of arguments. Arguments listed as "_" are ignored.
  // bool AuthorizeProgramToExecute(const string &path, const list<string>
  // &args);

  /// Check whether a principal is authorized to execute.
  /// @param name The tentative name of the hosted program.
  // bool IsAuthorizedToExecute(const string &name);

  /// Authorize a principal to claim a given subprincipal of the policy key,
  /// enabling principal to speak for that policy subprincipal.
  /// @param name The name of the principal.
  /// @param subprin A subprincipal of the policy.
  // bool AuthorizeNickname(const string &name, const string &subprin);

  /// Check whether a principal is authorized to claim a subprincipal name.
  /// @param name The name of a principal.
  /// @param subprin The policy subprincipal being claimed by that principal.
  // bool IsAuthorizedNickname(const string &name, const string &subprin);

  virtual bool GetSubprincipalName(string *subprin) const;

  /// This function will reload the configuration from disk, effectively making
  /// a deep copy. This is useful for passing out copies of TaoGuard objects to
  /// other classes that might want ownership of it.
  TaoDomain *DeepCopy();

  // Get the object representing all saved configuration parameters.
  // Subclasses or other classes can store data here before SaveConfig() is
  // called.
  TaoDomainConfig *GetConfig() { return config_.get(); }

  /// Parse all configuration parameters from the configuration file.
  virtual bool ParseConfig() { return true; }

  /// Save all configuration parameters to the configuration file and save all
  /// other state. Depending on the authorization regime, this may fail if the
  /// object is locked.
  virtual bool SaveConfig() const;

  /// Get the path to the configuration directory.
  string GetPath() const { return path_; }

  /// Get a path relative to the configuration directory.
  /// @param suffix The suffix to append to the configuration directory
  string GetPath(const string &suffix) const;

  // Get a fresh serial number for issuing x509 certificates.
  int GetFreshX509CertificateSerialNumber();

 protected:
  TaoDomain(const string &path, TaoDomainConfig *config);
  virtual bool Init(void) { return true; }

 private:
  /// Construct an object of the appropriate TaoDomain subclass. The caller
  /// should call either ParseConfig() to load keys and other date, or should
  /// generate keys and other state then call SaveConfig().
  /// @param config_text The protobuf TextFormat for TaoConfigDomain.
  /// @param path The location of the configuration file.
  static TaoDomain *CreateImpl(const string &config_text, const string &path);

  /// The path to the configuration file.
  string path_;

  /// The configuration parameters.
  unique_ptr<TaoDomainConfig> config_;

  /// The policy public key. If unlocked, also contains the private key.
  unique_ptr<Keys> keys_;

 private:
  DISALLOW_COPY_AND_ASSIGN(TaoDomain);
};
}  // namespace tao

#endif  // TAO_TAO_DOMAIN_H_
