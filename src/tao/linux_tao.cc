//  File: linux_tao.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An implementation of the Tao for the Linux
//  operating system.
//
//  Copyright (c) 2013, Google Inc.  All rights reserved.
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

#include <tao/linux_tao.h>
#include <tao/attestation.pb.h>
#include <tao/hosted_programs.pb.h>
#include <tao/keyczar_public_key.pb.h>
#include <tao/sealed_data.pb.h>
#include <tao/util.h>
#include <tao/whitelist_auth.h>

#include <keyczar/base/base64w.h>
#include <keyczar/rw/keyset_file_reader.h>
#include <keyczar/rw/keyset_file_writer.h>
#include <keyczar/rw/keyset_encrypted_file_reader.h>
#include <keyczar/rw/keyset_encrypted_file_writer.h>
#include <keyczar/base/file_path.h>
#include <keyczar/base/file_util.h>
#include <glog/logging.h>

#include <time.h>

#include <fstream>
#include <sstream>

using keyczar::base::Base64WEncode;
using keyczar::Crypter;
using keyczar::CryptoFactory;
using keyczar::Encrypter;
using keyczar::Keyczar;
using keyczar::Keyset;
using keyczar::KeysetMetadata;
using keyczar::KeyType;
using keyczar::KeyPurpose;
using keyczar::KeyStatus;
using keyczar::MessageDigestImpl;
using keyczar::RandImpl;
using keyczar::Signer;
using keyczar::Verifier;

using keyczar::base::CreateDirectory;
using keyczar::base::PathExists;
using keyczar::base::ScopedSafeString;

using keyczar::rw::KeysetReader;
using keyczar::rw::KeysetWriter;
using keyczar::rw::KeysetPBEJSONFileReader;
using keyczar::rw::KeysetPBEJSONFileWriter;
using keyczar::rw::KeysetEncryptedJSONFileReader;
using keyczar::rw::KeysetEncryptedJSONFileWriter;

using std::ifstream;
using std::istreambuf_iterator;
using std::ofstream;
using std::ios;
using std::stringstream;

namespace tao {

LinuxTao::LinuxTao(const string &secret_path, const string &key_path,
                   const string &pk_path, const string &whitelist_path,
                   const string &policy_pk_path, TaoChannel *host_channel,
                   TaoChannelFactory *channel_factory,
                   HostedProgramFactory *program_factory)
    : secret_path_(secret_path),
      key_path_(key_path),
      pk_path_(pk_path),
      policy_pk_path_(policy_pk_path),
      crypter_(nullptr),
      signer_(nullptr),
      policy_verifier_(nullptr),
      child_fds_{-1, -1},
      child_hash_(),
      whitelist_path_(whitelist_path),
      serialized_pub_key_(),
      pk_attest_(),
      host_channel_(host_channel),
      channel_factory_(channel_factory),
      program_factory_(program_factory),
      auth_manager_(nullptr),
      child_channel_(nullptr) {
  // leave setup for Init
}

bool LinuxTao::Init() {
  // load the public policy key
  policy_verifier_.reset(Verifier::Read(policy_pk_path_.c_str()));
  CHECK_NOTNULL(policy_verifier_.get());
  policy_verifier_->set_encoding(Keyczar::NO_ENCODING);

  scoped_ptr<WhitelistAuth> whitelist_auth(new WhitelistAuth());
  CHECK(whitelist_auth->Init(whitelist_path_, *policy_verifier_))
      << "Could not initialize the whitelist manager";
  auth_manager_.reset(whitelist_auth.release());

  // initialize the host channel
  CHECK(host_channel_->Init()) << "Could not initialize the host channel";

  // only keep the secret for the duration of this method:
  // long enough to unlock or create a sealed encryption key
  ScopedSafeString secret(new string());
  CHECK(getSecret(&secret))
      << "Could not generate (and seal) or unseal the secret using the Tao";
  VLOG(1) << "Got the secret";

  // now get our Crypter that was encrypted using this
  // secret or generate and encrypt a new one
  FilePath fp(key_path_);
  if (!PathExists(fp)) {
    CHECK(CreateDirectory(fp)) << "Could not create the key directory "
                               << key_path_;

    // create a new keyset
    CHECK(createKey(*secret)) << "Could not create crypter";
  } else {
    // read the crypter from the encrypted directory
    scoped_ptr<KeysetReader> reader(new KeysetPBEJSONFileReader(fp, *secret));
    crypter_.reset(Crypter::Read(*reader));
    CHECK_NOTNULL(crypter_.get());
  }

  crypter_->set_encoding(Keyczar::NO_ENCODING);

  // get a public-private key pair from the Tao key (either create and seal or
  // just unseal it).

  // First we need another copy of the crypter to give to the encrypted file
  // reader. By this point, however, there should be a copy on disk, so we can
  // use the secret again to get it.
  scoped_ptr<KeysetReader> crypter_reader(
      new KeysetPBEJSONFileReader(fp, *secret));
  scoped_ptr<Crypter> crypter(Crypter::Read(*crypter_reader));

  FilePath pk_fp(pk_path_);
  if (!PathExists(pk_fp)) {
    CHECK(CreateDirectory(pk_fp))
        << "Could not create the directory for a public-private key pair";
    CHECK(createPublicKey(crypter.release()))
        << "Could not create the publick key";
  } else {
    scoped_ptr<KeysetReader> reader(
        new KeysetEncryptedJSONFileReader(pk_fp, crypter.release()));
    signer_.reset(Signer::Read(*reader));
    CHECK_NOTNULL(signer_.get());
  }

  signer_->set_encoding(Keyczar::NO_ENCODING);

  KeyczarPublicKey kpk;
  if (!SerializePublicKey(*signer_, &kpk)) {
    LOG(ERROR) << "Could not serialize the public key for signing";
    return false;
  }

  if (!kpk.SerializeToString(&serialized_pub_key_)) {
    LOG(ERROR) << "Could not serialize the KeyczarPublicKey to a string";
    return false;
  }

  // Get an attestation for this key. In the chaining version, this
  // calls to the host for attestation. But in the key server version,
  // this needs to call to a key server. This virtual call can be
  // implemented to use either version.
  AttestToKey(serialized_pub_key_, &pk_attest_);

  VLOG(1) << "Finished tao initialization successfully";
  return true;
}

bool LinuxTao::getSecret(ScopedSafeString *secret) {
  CHECK_NOTNULL(secret);
  FilePath fp(secret_path_);
  if (!PathExists(fp)) {
    // generate a random value for the key and seal it, writing the result
    // into this file
    CHECK(host_channel_->GetRandomBytes(SecretSize, secret->get()))
        << "Could not generate a random secret to seal";

    // seal and save
    string sealed_secret;
    CHECK(host_channel_->Seal(*(secret->get()), &sealed_secret))
        << "Can't seal the secret";
    VLOG(2) << "Got a sealed secret of size "
            << static_cast<int>(sealed_secret.size());

    ofstream out_file(secret_path_.c_str(), ofstream::out);
    out_file.write(sealed_secret.data(), sealed_secret.size());
    out_file.close();

    VLOG(1) << "Sealed the secret";
  } else {
    // get the existing key blob and unseal it using the Tao
    ifstream in_file(secret_path_.c_str(), ifstream::in | ios::binary);
    string sealed_secret((istreambuf_iterator<char>(in_file)),
                         istreambuf_iterator<char>());

    VLOG(2) << "Trying to read a sealed secret of size "
            << static_cast<int>(sealed_secret.size());

    CHECK(host_channel_->Unseal(sealed_secret, secret->get()))
        << "Can't unseal the secret";
    VLOG(2) << "Unsealed a secret of size "
            << static_cast<int>(secret->get()->size());
  }

  return true;
}

bool LinuxTao::createPublicKey(Encrypter *crypter) {
  FilePath fp(pk_path_);
  scoped_ptr<KeysetWriter> writer(
      new KeysetEncryptedJSONFileWriter(fp, crypter));

  CHECK_NOTNULL(writer.get());
  return CreateKey(writer.get(), KeyType::ECDSA_PRIV,
                   KeyPurpose::SIGN_AND_VERIFY, "linux_tao_pk", &signer_);
}

bool LinuxTao::createKey(const string &secret) {
  FilePath fp(key_path_);
  scoped_ptr<KeysetWriter> writer(new KeysetPBEJSONFileWriter(fp, secret));
  CHECK_NOTNULL(writer.get());
  return CreateKey(writer.get(), KeyType::AES, KeyPurpose::DECRYPT_AND_ENCRYPT,
                   "linux_tao", &crypter_);
}

bool LinuxTao::Destroy() { return true; }

bool LinuxTao::StartHostedProgram(const string &path,
                                  const list<string> &args) {
  // TODO(tmroeder): add support for multiple child programs
  if (!child_hash_.empty()) {
    LOG(ERROR) << "Cannot start a second program under the tao bootstrap";
    return false;
  }

  // first check to make sure that this program is authorized

  ifstream program_stream(path.c_str());
  stringstream program_buf;
  program_buf << program_stream.rdbuf();

  // TODO(tmroeder): take in the right hash type and use it here. For
  // now, we just assume that it's SHA256
  MessageDigestImpl *sha256 = CryptoFactory::SHA256();
  string digest;
  if (!sha256->Digest(program_buf.str(), &digest)) {
    LOG(ERROR) << "Could not compute the digest over the file";
    return false;
  }

  string serialized_digest;
  if (!Base64WEncode(digest, &serialized_digest)) {
    LOG(ERROR) << "Could not encode the digest as Base64W";
    return false;
  }

  if (!auth_manager_->IsAuthorized(path, serialized_digest)) {
    LOG(ERROR) << "Program " << path << " with digest " << serialized_digest
               << " is not authorized";
    return false;
  }

  LOG(INFO) << "The program " << path << " with digest " << serialized_digest << " is authorized";

  child_hash_ = digest;

  // TODO(tmroeder): for now, we only start a single child
  child_channel_.reset(channel_factory_->CreateTaoChannel());
  if (!program_factory_->CreateHostedProgram(path, args, *child_channel_)) {
    LOG(ERROR) << "Could not start the hosted program";
    return false;
  }

  // TODO(tmroeder): add this to the MultiplexTaoChannel when we have that
  // implemented
  // bool rv = child_channel_->Listen(this);
  // if (!rv) {
  //   LOG(ERROR) << "Server listening failed";
  //   return false;
  // }

  return true;
}

bool LinuxTao::GetRandomBytes(size_t size, string *bytes) const {
  // just ask keyczar for random bytes, which will ask OpenSSL in turn
  if (!host_channel_->GetRandomBytes(size, bytes)) {
    LOG(ERROR) << "Could not generate random bytes";
    return false;
  }

  return true;
}

// TODO(tmroeder): the sealing/attestation operations need to take the
// measurement of the child as input.
bool LinuxTao::Seal(const string &data, string *sealed) const {
  if (child_hash_.empty()) {
    LOG(ERROR) << "Cannot seal to an empty child";
    return false;
  }

  SealedData sd;
  sd.set_hash(child_hash_);

  // TODO(tmroeder): generalize to other hash algorithms
  sd.set_hash_alg("SHA256");
  sd.set_data(data);

  string serialized_sd;
  if (!sd.SerializeToString(&serialized_sd)) {
    LOG(ERROR) << "Could not serialize the SealedData";
    return false;
  }

  // encrypt it using our symmetric key
  if (!crypter_->Encrypt(serialized_sd, sealed)) {
    LOG(ERROR) << "Could not seal the data";
    return false;
  }

  return true;
}

bool LinuxTao::Unseal(const string &sealed, string *data) const {
  // decrypt it using our symmetric key
  string temp_decrypted;
  if (!crypter_->Decrypt(sealed, &temp_decrypted)) {
    LOG(ERROR) << "Could not decrypt the sealed data";
    return false;
  }

  // try to parse it as SealedData, and check the hash to make sure it matches
  SealedData sd;
  if (!sd.ParseFromString(temp_decrypted)) {
    // note that this is safe, since we always use authenticated encryption
    LOG(ERROR) << "Could not parse the decrypted data as SealedData";
    return false;
  }

  if (child_hash_.compare(sd.hash()) != 0) {
    LOG(ERROR) << "This data was not sealed to this program";
    return false;
  }

  data->assign(sd.data().data(), sd.data().size());

  return true;
}

bool LinuxTao::Attest(const string &data, string *attestation) const {
  if (child_hash_.empty()) {
    LOG(ERROR) << "Cannot create an attestation when there is no child process";
    return false;
  }

  if (!attestation) {
    LOG(ERROR) << "attestation was null";
    return false;
  }

  Statement s;
  time_t cur_time;
  time(&cur_time);

  s.set_time(cur_time);
  s.set_expiration(cur_time + AttestationTimeout);
  s.set_data(data);
  s.set_hash_alg("SHA256");
  s.set_hash(child_hash_);

  string serialized_statement;
  if (!s.SerializeToString(&serialized_statement)) {
    LOG(ERROR) << "Could not serialize the statement";
    return false;
  }

  string signature;
  if (!signer_->Sign(serialized_statement, &signature)) {
    LOG(ERROR) << "Could not sign the attestation";
    return false;
  }

  Attestation a;
  a.set_type(INTERMEDIATE);
  a.set_serialized_statement(serialized_statement);
  a.set_signature(signature);

  string *mutable_cert = a.mutable_cert();
  if (!pk_attest_.SerializeToString(mutable_cert)) {
    LOG(ERROR) << "Could not serialize the certificate for our public key";
    return false;
  }

  if (!a.SerializeToString(attestation)) {
    LOG(ERROR) << "Could not serialize the attestation";
    return false;
  }

  return true;
}

bool LinuxTao::VerifyAttestation(const string &attestation,
                                 string *data) const {
  Attestation a;
  if (!a.ParseFromString(attestation)) {
    LOG(ERROR) << "Could not deserialize an Attestation";
    return false;
  }

  // Verify the cert to get the data back.
  // If there is an attestation, then recurse to check the attestation
  // of the public key. Otherwise, this must be the policy key.
  if (a.has_cert()) {
    // Make sure we're supposed to recurse here.
    if (a.type() != INTERMEDIATE) {
      LOG(ERROR)
          << "Expected this Attestation to be INTERMEDIATE, but it was not";
      return false;
    }

    // Recurse on the cert Attestation and get the serialized key back
    string key_data;
    if (!VerifyAttestation(a.cert(), &key_data)) {
      LOG(ERROR) << "Could not verify the public_key attestation";
      return false;
    }

    KeyczarPublicKey kpk;
    if (!kpk.ParseFromString(key_data)) {
      LOG(ERROR) << "Could not deserialize the public key for this attestation";
      return false;
    }

    // Get a Keyset corresponding to this public key
    Keyset *k = nullptr;
    if (!DeserializePublicKey(kpk, &k)) {
      LOG(ERROR) << "Could not deserialize the public key";
      return false;
    }

    scoped_ptr<Verifier> v(new Verifier(k));
    v->set_encoding(Keyczar::NO_ENCODING);
    if (!v->Verify(a.serialized_statement(), a.signature())) {
      LOG(ERROR) << "The statement in an attestation did not have a valid "
                    "signature from its public key";
      return false;
    }
  } else {
    if (a.type() != ROOT) {
      LOG(ERROR) << "This is not a ROOT attestation, but it claims to be "
                    "signed with the public key";
      return false;
    }

    // Verify against the policy key.
    if (!policy_verifier_->Verify(a.serialized_statement(), a.signature())) {
      LOG(ERROR) << "Verification failed with the policy key";
      return false;
    }
  }

  Statement s;
  if (!s.ParseFromString(a.serialized_statement())) {
    LOG(ERROR) << "Could not parse the serialized statement in an attestation";
    return false;
  }

  // check that the time isn't too far in the past
  time_t cur_time;
  time(&cur_time);

  time_t past_time = s.time();
  if (cur_time - past_time > AttestationTimeout) {
    LOG(ERROR) << "The attestation was too old";
    return false;
  }

  // check that this is a whitelisted program
  // TODO(tmroeder): make sure this is using the right hash algorithm, too
  if (!auth_manager_->IsAuthorized(s.hash())) {
    LOG(ERROR) << "The attested program was not a whitelisted program";
    return false;
  }

  data->assign(s.data().data(), s.data().size());

  VLOG(1) << "The attestation passed verification";

  return true;
}

bool LinuxTao::AttestToKey(const string &serialized_key,
                           Attestation *attest) const {
  string serialized_attestation;
  if (!host_channel_->Attest(serialized_key, &serialized_attestation)) {
    LOG(ERROR) << "Could not get an attestation to the serialized key";
    return false;
  }

  if (!attest->ParseFromString(serialized_attestation)) {
    LOG(ERROR) << "Could not deserialize the attestation to our key";
    return false;
  }

  return true;
}
}  // namespace cloudproxy
