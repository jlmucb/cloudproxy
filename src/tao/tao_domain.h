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

#include <string>

#include <keyczar/base/scoped_ptr.h>

#include "tao/keys.h"
#include "tao/tao_auth.h"

using std::string;

class DictionaryValue;

namespace keyczar {
class Crypter;
class Signer;
class Verifier;
}  // namespace keyczar

namespace tao {
class Attestation;
class Keys;
class Statement;

/// A TaoDomain stores and manages a set of configuration parameters for a
/// single administrative domain, including a policy key pair, the host:port
/// location to access a Tao CA (if available). Classes that implement TaoDomain
/// also implements TaoAuth to govern authorization for the administrative
/// domain, and they store and manage any configuration necessary for that
/// purpose, e.g. the location of whitelist files.
///
/// Except for a password used to encrypt the policy private key, all
/// configuration data for TaoDomain is stored in a JSON file, typically named
/// "tao.config". This configuration file contains the locations of all other
/// files and directories needed by TaoDomain. File and directory paths within
/// the tao.config file are relative to the location of the tao.config file
/// itself.
class TaoDomain : public TaoAuth {
 public:
  virtual ~TaoDomain();

  // TODO(kwalsh) use protobuf instead of json?
  /// An example json string useful for constructing domains for testing
  constexpr static auto ExampleWhitelistAuthDomain =
      "{\n"
      "   \"name\": \"tao example whitelist domain\",\n"
      "\n"
      "   \"policy_keys_path\":     \"policy_keys\",\n"
      "   \"policy_x509_details\":  \"country: \\\"US\\\" state: "
      "\\\"Washington\\\" organization: \\\"Google\\\" commonname: \\\"tao "
      "example domain\\\"\",\n"
      "   \"policy_x509_last_serial\": 0,\n"
      "\n"
      "   \"auth_type\": \"whitelist\",\n"
      "   \"signed_whitelist_path\": \"whitelist\",\n"
      "\n"
      "   \"tao_ca_host\": \"localhost\",\n"
      "   \"tao_ca_port\": \"11238\"\n"
      "}";

  /// An example json string useful for constructing domains for testing
  constexpr static auto ExampleRootAuthDomain =
      "{\n"
      "   \"name\": \"tao example root domain\",\n"
      "\n"
      "   \"policy_keys_path\":     \"policy_keys\",\n"
      "   \"policy_x509_details\":  \"country: \\\"US\\\" state: "
      "\\\"Washington\\\" organization: \\\"Google\\\" commonname: \\\"tao "
      "example domain\\\"\",\n"
      "   \"policy_x509_last_serial\": 0,\n"
      "\n"
      "   \"auth_type\": \"root\",\n"
      "\n"
      "   \"tao_ca_host\": \"localhost\",\n"
      "   \"tao_ca_port\": \"11238\"\n"
      "}";

  /// Name strings for name:value pairs in JSON config.
  constexpr static auto JSONName = "name";
  constexpr static auto JSONPolicyKeysPath = "policy_keys_path";
  constexpr static auto JSONPolicyX509Details = "policy_x509_details";
  constexpr static auto JSONPolicyX509LastSerial = "policy_x509_last_serial";
  constexpr static auto JSONTaoCAHost = "tao_ca_host";
  constexpr static auto JSONTaoCAPort = "tao_ca_port";
  constexpr static auto JSONAuthType = "auth_type";

  /// Initialize a new TaoDomain and write its configuration files to a
  /// directory. This creates the directory if needed, creates a policy key
  /// pair, and initializes default state for authorization, e.g. an empty
  /// whitelist.
  /// @param initial_config A JSON string containing the initial configuration
  /// for this TaoDomain.
  /// @param path The location to store the configuration file.
  /// @param password A password for encrypting the policy private key.
  static TaoDomain *Create(const string &initial_config, const string &path,
                           const string &password);

  /// Initialize a TaoDomain from an existing configuration file. The object
  /// will be "locked", meaning that the policy private signing key will not be
  /// available, new whitelists or attestations can not be signed, etc.
  /// @param path The location of the existing configuration file.
  static TaoDomain *Load(const string &path) { return Load(path, ""); }

  /// Initialize a TaoDomain from an existing configuration file.
  /// @param path The location of the existing configuration file.
  /// @param password The password to unlock the policy private key. If password
  /// is emptystring, then the TaoDomain object will be "locked", meaning that
  /// the policy private signing key will not be available, new whitelists or
  /// attestations can not be signed, etc.
  static TaoDomain *Load(const string &path, const string &password);

  /// Get the name of this administrative domain.
  string GetName() const { return GetConfigString(JSONName); }

  /// Get details for x509 policy certificates.
  string GetPolicyX509Details() const {
    return GetConfigString(JSONPolicyX509Details);
  }

  /// Get the host for the Tao CA. This returns emptystring if there is no Tao
  /// CA for this administrative domain.
  string GetTaoCAHost() const { return GetConfigString(JSONTaoCAHost); }

  /// Get the port for the Tao CA. This is undefined if there is no Tao CA for
  /// this administrative domain.
  string GetTaoCAPort() const { return GetConfigString(JSONTaoCAPort); }

  /// Get a string describing the authorization regime governing this
  /// administrative domain.
  string GetAuthType() const { return GetConfigString(JSONAuthType); }

  /// Get the policy key signer. This returns nullptr if the object is locked.
  keyczar::Signer *GetPolicySigner() const { return keys_->Signer(); }

  /// Get the policy key verifier.
  keyczar::Verifier *GetPolicyVerifier() const { return keys_->Verifier(); }

  /// Get the policy keys.
  Keys *GetPolicyKeys() const { return keys_.get(); }

  /// Create a attestation signed by the policy private key.
  /// Typical statements might assert:
  ///     (i) that a given aik is trusted (on certain matters)
  ///    (ii) that a given fake_tpm is trusted (on certain matters)
  ///   (iii) that a given program key speaks for a specific name.
  /// @param s[in,out] The statement to be attested to. If the statement
  /// timestamp is missing, it will be filled with the current time. If the
  /// statement expiration is missing, it will be set to some default duration
  /// after the timestamp.
  /// @param attestation[out] The signed attestation.
  bool AttestByRoot(Statement *s, Attestation *attestation) const;
  bool AttestByRoot(Statement *s, string *serialized_attestation) const;

  /// Check a signature made by the policy key.
  bool CheckRootSignature(const Attestation &a) const;

  /// Authorize a new hosted program to execute. The program's hash will be
  /// computed and added to the set of hashes authorized to execute, and the
  /// program's hash will be associated with the program name so that the hash
  /// is authorized to speak for that name. This is equivalent to
  /// Authorize(BaseName(path), Sha256, SHA256(Contents(path))).
  /// @param path The location of the program binary to be added. The last
  /// component of the path will be used as the program name, and the contents
  /// of the program binary will be hashed.
  bool AuthorizeProgram(const string &path);

  /// This function will reload the configuration from disk, effectively making
  /// a deep copy. This is useful for passing out copies of TaoAuth objects to
  /// other classes that might want ownership of it.
  TaoDomain *DeepCopy();

  // Get the object representing all saved configuration parameters.
  // Subclasses or other classes can store data here before SaveConfig() is
  // called.
  DictionaryValue *GetConfig() { return config_.get(); }

  /// Get a string configuration parameter. If the parameter is not found,
  /// this returns emptystring.
  /// @param name The configuration parameter name to look up
  string GetConfigString(const string &name) const;

  /// Get a path configuration parameter, relative to the config directory.
  /// @param name The configuration parameter name to look up
  string GetConfigPath(const string &name) const {
    return GetPath(GetConfigString(name));
  }

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
  TaoDomain(const string &path, DictionaryValue *value);

 private:
  /// Construct an object of the appropriate TaoDomain subclass. The caller
  /// should call either ParseConfig() to load keys and other date, or should
  /// generate keys and other state then call SaveConfig().
  /// @param config The json encoded configuration data.
  /// @param path The location of the configuration file.
  static TaoDomain *CreateImpl(const string &config, const string &path);

  /// The path to the configuration file.
  string path_;

  /// The dictionary of configuration parameters.
  scoped_ptr<DictionaryValue> config_;

  /// The policy public key. If unlocked, also contains the private key.
  scoped_ptr<Keys> keys_;

 private:
  DISALLOW_COPY_AND_ASSIGN(TaoDomain);
};
}  // namespace tao

#endif  // TAO_TAO_DOMAIN_H_
