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

#include "tao/linux_tao.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>

#include <fstream>
#include <sstream>

#include <glog/logging.h>
#include <keyczar/base/file_path.h>
#include <keyczar/base/file_util.h>
#include <keyczar/base/base64w.h>
#include <keyczar/keyczar.h>
#include <keyczar/rw/keyset_encrypted_file_reader.h>
#include <keyczar/rw/keyset_encrypted_file_writer.h>
#include <keyczar/rw/keyset_file_reader.h>
#include <keyczar/rw/keyset_file_writer.h>
#include <keyczar/crypto_factory.h>

#include "tao/attestation.pb.h"
#include "tao/hosted_programs.pb.h"
#include "tao/hosted_program_factory.h"
#include "tao/keyczar_public_key.pb.h"
#include "tao/sealed_data.pb.h"
#include "tao/tao_auth.h"
#include "tao/tao_channel.h"
#include "tao/tao_child_channel.h"
#include "tao/util.h"

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
using keyczar::base::Base64WEncode;
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
                   const string &pk_path, const string &policy_pk_path,
                   TaoChildChannel *host_channel, TaoChannel *child_channel,
                   HostedProgramFactory *program_factory, TaoAuth *auth_manager,
                   const string &ca_host, const string &ca_port)
    : secret_path_(secret_path),
      key_path_(key_path),
      pk_path_(pk_path),
      policy_pk_path_(policy_pk_path),
      crypter_(nullptr),
      signer_(nullptr),
      policy_verifier_(nullptr),
      serialized_pub_key_(),
      pk_attest_(),
      host_channel_(host_channel),
      child_channel_(child_channel),
      program_factory_(program_factory),
      auth_manager_(auth_manager),
      running_children_(),
      ca_host_(ca_host),
      ca_port_(ca_port) {
  // leave setup for Init
}

bool LinuxTao::Init() {
  // load the public policy key
  policy_verifier_.reset(Verifier::Read(policy_pk_path_.c_str()));
  CHECK_NOTNULL(policy_verifier_.get());
  policy_verifier_->set_encoding(Keyczar::NO_ENCODING);

  // initialize the host channel
  CHECK(host_channel_->Init()) << "Could not initialize the host channel";

  // only keep the secret for the duration of this method:
  // long enough to unlock or create a sealed encryption key
  ScopedSafeString secret(new string());
  CHECK(getSecret(&secret))
      << "Could not generate (and seal) or unseal the secret using the Tao";

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

  if (!attestToKey(serialized_pub_key_, &pk_attest_)) {
    LOG(ERROR) << "Could not get an attestation for the LinuxTao public key";
    return false;
  }

  // The Trusted Computing Certificate Authority can take a cert chain and
  // produce a shortened form that consists of a single attestation by the
  // policy key. Use it if requested.
  if (!ca_host_.empty()) {
    if (!getCertFromCA(&pk_attest_)) {
      LOG(ERROR) << "Could not get a new certificate from the TCCA";
      return false;
    }
  }

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
                                  const list<string> &args,
				  string *identifier) {
  string child_hash;
  if (!program_factory_->HashHostedProgram(path, args, &child_hash)) {
    LOG(ERROR) << "Could not hash the hosted program";
    return false;
  }

  {
    lock_guard<mutex> l(auth_m_);
    if (!auth_manager_->IsAuthorized(path, child_hash)) {
      LOG(ERROR) << "Program " << path << " with digest " << child_hash
                 << " is not authorized";
      return false;
    }
  }

  VLOG(2) << "The program " << path << " with digest " << child_hash
          << " is authorized";

  {
    lock_guard<mutex> l(data_m_);
    auto child_it = running_children_.find(child_hash);
    if (running_children_.end() != child_it) {
      LOG(ERROR) << "An instance of the program " << path << " with digest "
                 << child_hash << " is already running";
      return false;
    }

    running_children_.insert(child_hash);
  }

  string child_params;
  if (!child_channel_->AddChildChannel(child_hash, &child_params)) {
    LOG(ERROR) << "Could not add a channel to connect to a child with hash "
               << child_hash;
    return false;
  }

  list<string> program_args(args.begin(), args.end());

  // The convention is that the arguments are Base64W encoded as the last
  // argument in the list. The factory chooses how to handle the params.
  string encoded_params;
  if (!Base64WEncode(child_params, &encoded_params)) {
    LOG(ERROR) << "Could not encode the child params for the program";
    return false;
  }

  program_args.push_back(encoded_params);

  if (!program_factory_->CreateHostedProgram(path, program_args, child_hash,
                                             *child_channel_, identifier)) {
    LOG(ERROR) << "Could not start the hosted program";
    return false;
  }

  return true;
}

bool LinuxTao::RemoveHostedProgram(const string &child_hash) {
  {
    lock_guard<mutex> l(data_m_);
    auto child_it = running_children_.find(child_hash);
    if (running_children_.end() == child_it) {
      LOG(ERROR) << "An instance of the program  with digest " << child_hash
                 << " is not running";
      return false;
    }

    running_children_.erase(child_it);
  }

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

bool LinuxTao::Seal(const string &child_hash, const string &data,
                    string *sealed) const {
  {
    lock_guard<mutex> l(data_m_);
    auto child_it = running_children_.find(child_hash);
    if (running_children_.end() == child_it) {
      LOG(ERROR) << "The program with digest " << child_hash << " was not a "
                 << "program that was executing";
      return false;
    }
  }

  SealedData sd;
  sd.set_hash(child_hash);

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

bool LinuxTao::Unseal(const string &child_hash, const string &sealed,
                      string *data) const {
  {
    lock_guard<mutex> l(data_m_);
    auto child_it = running_children_.find(child_hash);
    if (running_children_.end() == child_it) {
      LOG(ERROR) << "The program with digest " << child_hash << " was not a "
                 << "program that was executing";
      return false;
    }
  }

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

  if (child_hash.compare(sd.hash()) != 0) {
    LOG(ERROR) << "This data was not sealed to this program";
    return false;
  }

  data->assign(sd.data().data(), sd.data().size());

  return true;
}

bool LinuxTao::Attest(const string &child_hash, const string &data,
                      string *attestation) const {
  {
    lock_guard<mutex> l(data_m_);
    auto child_it = running_children_.find(child_hash);
    if (running_children_.end() == child_it) {
      LOG(ERROR) << "The program with digest " << child_hash << " was not a "
                 << "program that was executing";
      return false;
    }
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
  s.set_hash(child_hash);

  string serialized_statement;
  if (!s.SerializeToString(&serialized_statement)) {
    LOG(ERROR) << "Could not serialize the statement";
    return false;
  }

  string signature;
  if (!SignData(serialized_statement, AttestationSigningContext, &signature,
                signer_.get())) {
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

bool LinuxTao::attestToKey(const string &serialized_key, Attestation *attest) {
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

bool LinuxTao::Listen() {
  // All the work of listening and calling the LinuxTao is done in the
  // TaoChannel implementation. See, e.g., PipeTaoChannel
  return child_channel_->Listen(this);
}

bool LinuxTao::getCertFromCA(Attestation *attest) {
  ScopedFd sock(new int(-1));
  if (!ConnectToTCPServer(ca_host_, ca_port_, sock.get())) {
    LOG(ERROR) << "Could not connect to tcca";
    return false;
  }

  // The TCCA will convert our attestation into a new attestation signed by the
  // policy key.
  if (!tao::SendMessage(*sock, *attest)) {
    LOG(ERROR) << "Could not send our attestation to the TCCA";
    return false;
  }

  Attestation new_attest;
  if (!tao::ReceiveMessage(*sock, &new_attest)) {
    LOG(ERROR) << "Could not get the new attestation from the TCCA";
    return false;
  }

  // Check the attestation to make sure it passes verification.
  if (new_attest.type() != ROOT) {
    LOG(ERROR) << "Expected a Root attestation from TCCA";
    return false;
  }

  string serialized;
  if (!new_attest.SerializeToString(&serialized)) {
    LOG(ERROR) << "Could not serialize the new attestation";
    return false;
  }

  string dummy_data;
  if (!auth_manager_->VerifyAttestation(serialized, &dummy_data)) {
    LOG(ERROR) << "The attestation did not pass verification";
    return false;
  }

  if (new_attest.serialized_statement().compare(
          attest->serialized_statement()) !=
      0) {
    LOG(ERROR) << "The statement in the new attestation doesn't match our "
                  "original statement";
    return false;
  }

  attest->Clear();
  attest->CopyFrom(new_attest);
  return true;
}
}  // namespace cloudproxy
