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

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include <list>
#include <mutex>

#include <glog/logging.h>
#include <keyczar/base/base64w.h>
#include <keyczar/base/file_path.h>
#include <keyczar/base/file_util.h>

#include "tao/attestation.pb.h"
#include "tao/hosted_program_factory.h"
#include "tao/hosted_programs.pb.h"
#include "tao/keyczar_public_key.pb.h"
#include "tao/sealed_data.pb.h"
#include "tao/tao_auth.h"
#include "tao/tao_channel.h"
#include "tao/tao_child_channel.h"
#include "tao/util.h"

using std::lock_guard;
using std::mutex;

using keyczar::base::Base64WEncode;
using keyczar::base::CreateDirectory;
using keyczar::base::PathExists;
using keyczar::base::ReadFileToString;
using keyczar::base::ScopedSafeString;
using keyczar::base::WriteStringToFile;

namespace tao {

bool LinuxTao::Init() {
  // initialize the host channel
  if (!host_channel_->Init()) {
    LOG(ERROR) << "Could not initialize the host channel";
    return false;
  }

  FilePath fp(keys_path_);
  string secret_path = fp.Append(tao::keys::SealKeySecretSuffix).value();
  string sealing_key_path = fp.Append(tao::keys::SealKeySuffix).value();
  string signing_key_path = fp.Append(tao::keys::SignPrivateKeySuffix).value();
  string attestation_path =
      fp.Append(tao::keys::SignKeyAttestationSuffix).value();

  // only keep the secret for the duration of this method:
  // long enough to unlock or create sealing and signing keys
  ScopedSafeString secret(new string());

  // The secret, the keys, and the attestation are all bound together,
  // so we either generate them all anew or we use only the existing ones.
  if (!PathExists(FilePath(secret_path))) {
    if (!MakeSecret(&secret)) {
      LOG(ERROR) << "Could not generate and seal a secret using the Tao";
      return false;
    }
    VLOG(2) << "LinuxTao: Generating sealing key " << sealing_key_path;
    if (!GenerateCryptingKey(sealing_key_path, "linux_tao_sealing_key", *secret,
                             &crypter_)) {
      LOG(ERROR) << "Could not generate a sealing key";
      return false;
    }
    VLOG(2) << "LinuxTao: Generating signing key " << signing_key_path;
    if (!GenerateEncryptedSigningKey(signing_key_path, "" /* no pub path */,
                                     "linux_tao_signing_key", sealing_key_path,
                                     *secret, &signer_)) {
      LOG(ERROR) << "Could not generate a signing key";
      return false;
    }
    VLOG(2) << "Linux Tao: Obtaining attestation from the Tao";
    Attestation a;
    if (!GetTaoAttestation(&a)) {
      LOG(ERROR) << "Could not get an attestation from the Tao";
      return false;
    }
    // The Tao Certificate Authority can take a cert chain and produce a
    // shortened form that consists of a single attestation by the policy key.
    // Use it if available.
    if (!admin_->GetTaoCAHost().empty()) {
      VLOG(2) << "LinuxTao: Obtaining condensed attestation from the TCCA";
      if (!GetTaoCAAttestation(&a)) {
        LOG(ERROR) << "Could not get a new attestation from the TCCA";
        return false;
      }
    }
    if (!a.SerializeToString(&attestation_)) {
      LOG(ERROR) << "Could not serialize the attestation for our signing key";
      return false;
    }
    if (!WriteStringToFile(attestation_path, attestation_)) {
      LOG(ERROR) << "Could not store the attestation for our signing key";
      return false;
    }
  } else {
    if (!GetSecret(&secret)) {
      LOG(ERROR) << "Could not unseal a secret using the Tao";
      return false;
    }
    VLOG(2) << "LinuxTao: Using sealing key " << sealing_key_path;
    if (!LoadCryptingKey(sealing_key_path, *secret, &crypter_)) {
      LOG(ERROR) << "Could not load the sealing key";
      return false;
    }
    VLOG(2) << "LinuxTao: Using signing key " << signing_key_path;
    if (!LoadEncryptedSigningKey(signing_key_path, sealing_key_path, *secret,
                                 &signer_)) {
      LOG(ERROR) << "Could not load the signing key";
      return false;
    }
    if (!ReadFileToString(attestation_path, &attestation_)) {
      LOG(ERROR) << "Could not load attestation for signing key";
      return false;
    }
  }
  VLOG(1) << "LinuxTao: Initialization finished successfully";
  return true;
}

bool LinuxTao::MakeSecret(ScopedSafeString *secret) {
  if (!host_channel_->GetRandomBytes(SecretSize, secret->get())) {
    LOG(ERROR) << "Could not generate a random secret to seal";
    return false;
  }
  string sealed_secret;
  if (!host_channel_->Seal(*(secret->get()), &sealed_secret)) {
    LOG(ERROR) << "Can't seal the secret";
    return false;
  }
  FilePath fp(keys_path_);
  FilePath secret_path(fp.Append(tao::keys::SealKeySecretSuffix));
  if (!CreateDirectory(secret_path.DirName())) {
    LOG(ERROR) << "Can't create sealed secret directory ";
    return false;
  }
  if (!WriteStringToFile(secret_path, sealed_secret)) {
    LOG(ERROR) << "Can't write the sealed secret to " << secret_path.value();
    return false;
  }
  VLOG(2) << "Sealed a secret of size "
          << static_cast<int>(secret->get()->size());
  return true;
}

bool LinuxTao::GetSecret(ScopedSafeString *secret) {
  // get the existing key blob and unseal it using the Tao
  string sealed_secret;
  FilePath fp(keys_path_);
  FilePath secret_path(fp.Append(tao::keys::SealKeySecretSuffix));
  if (!ReadFileToString(secret_path, &sealed_secret)) {
    LOG(ERROR) << "Can't read the sealed secret";
    return false;
  }
  if (!host_channel_->Unseal(sealed_secret, secret->get())) {
    LOG(ERROR) << "Can't unseal the secret";
    return false;
  }
  VLOG(2) << "Unsealed a secret of size "
          << static_cast<int>(secret->get()->size());
  return true;
}

bool LinuxTao::StartHostedProgram(const string &path, const list<string> &args,
                                  string *identifier) {
  string child_hash;
  string child_name = FilePath(path).BaseName().value();
  if (!program_factory_->HashHostedProgram(path, args, &child_hash)) {
    LOG(ERROR) << "Could not hash the hosted program";
    return false;
  }

  {
    lock_guard<mutex> l(auth_m_);
    // TODO(kwalsh) hash alg should come from ProgramFactory::HashHostedProgram
    if (!admin_->IsAuthorized(child_hash, TaoAuth::Sha256, child_name)) {
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
  sd.set_hash_alg(TaoAuth::Sha256);
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

  Statement s;
  s.set_data(data);
  s.set_hash_alg(TaoAuth::Sha256);
  s.set_hash(child_hash);

  return GenerateAttestation(signer_.get(), attestation_, &s, attestation);
}

bool LinuxTao::GetTaoAttestation(Attestation *attest) {
  string serialized_key = SerializePublicKey(*signer_);
  if (serialized_key.empty()) {
    LOG(ERROR) << "Could not serialize signing key";
    return false;
  }
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

bool LinuxTao::GetTaoCAAttestation(Attestation *attest) {
  string host = admin_->GetTaoCAHost();
  string port = admin_->GetTaoCAPort();
  ScopedFd sock(new int(-1));
  if (!ConnectToTCPServer(host, port, sock.get())) {
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
  if (!admin_->VerifyAttestation(serialized, &dummy_data)) {
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
}  // namespace tao
