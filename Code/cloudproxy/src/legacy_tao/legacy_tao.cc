//  File: legacy_tao.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An implementation of the Tao over the original
//  CloudProxy tao
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

#include "legacy_tao/legacy_tao.h"
#include "cloudproxy/util.h"
#include "tao/attestation.pb.h"
#include "tao/hosted_programs.pb.h"
#include "tao/keyczar_public_key.pb.h"
#include "tao/quote.pb.h"
#include "tao/sealed_data.pb.h"
#include "tao/pipe_tao_channel.h"
#include "tao/whitelist_authorization_manager.h"

#include <keyczar/base/base64w.h>
#include <keyczar/rw/keyset_file_reader.h>
#include <keyczar/rw/keyset_file_writer.h>
#include <keyczar/rw/keyset_encrypted_file_reader.h>
#include <keyczar/rw/keyset_encrypted_file_writer.h>
#include <keyczar/base/file_path.h>
#include <keyczar/base/file_util.h>
#include <glog/logging.h>

// minimal amount of code needed from the old CloudProxy implementation to
// bootstrap into a new one
#include <jlmcrypto.h>
#include <cert.h>
#include <keys.h>
#include <logging.h>
#include <policyCert.inc>
#include <validateEvidence.h>

#include <time.h>

#include <fstream>
#include <sstream>

using cloudproxy::SerializePublicKey;
using cloudproxy::DeserializePublicKey;

using tao::Attestation;
using tao::HostedProgram;
using tao::KeyczarPublicKey;
using tao::PipeTaoChannel;
using tao::SealedData;
using tao::SignedAttestation;
using tao::SignedWhitelist;
using tao::TaoAuthorizationManager;
using tao::Whitelist;
using tao::WhitelistAuthorizationManager;

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
using std::ofstream;
using std::ios;
using std::stringstream;

namespace legacy_tao {

LegacyTao::LegacyTao(const string &secret_path, const string &directory,
                     const string &key_path, const string &pk_path,
                     const string &whitelist_path, const string &policy_pk_path)
    : secret_path_(secret_path),
      directory_(directory),
      key_path_(key_path),
      pk_path_(pk_path),
      policy_pk_path_(policy_pk_path),
      tao_host_(new taoHostServices()),
      tao_env_(new taoEnvironment()),
      crypter_(nullptr),
      signer_(nullptr),
      policy_verifier_(nullptr),
      child_fds_({-1, -1}),
      child_hash_(),
      whitelist_path_(whitelist_path),
      auth_manager_(new WhitelistAuthorizationManager()),
      legacy_policy_cert_(nullptr) {
  // leave setup for Init
}

bool LegacyTao::Init() {
  // load the public policy key
  policy_verifier_.reset(Verifier::Read(policy_pk_path_.c_str()));
  CHECK_NOTNULL(policy_verifier_.get());
  policy_verifier_->set_encoding(Keyczar::NO_ENCODING);

  CHECK(auth_manager_->Init(whitelist_path_, *policy_verifier_))
      << "Could not initialize the whitelist manager";

  // initialize jlmcrypto from the legacy tao; this is required to use
  // any of the original tao
  CHECK(initAllCrypto()) << "Could not initialize jlmcrypto";

  CHECK(initTao()) << "Could not initialize the Tao";
  VLOG(1) << "Initialized the Tao";

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

  // set up the legacy policy key
  legacy_policy_cert_.reset(new PrincipalCert());
  CHECK(legacy_policy_cert_->init(const_cast<const char*>(reinterpret_cast<char *>(tao_env_->m_policyKey)))) << "Could not initialize the legacy policy public key";
  CHECK(legacy_policy_cert_->parsePrincipalCertElements()) << "Could not finish legacy policy public key initialization";

  VLOG(1) << "Finished legacy tao initialization successfully";
  return true;
}

bool LegacyTao::initTao() {
  const char *directory = directory_.c_str();
  const char **parameters = &directory;
  int parameterCount = 1;

  try {
    // init host
    CHECK(tao_host_->HostInit(PLATFORMTYPELINUX, parameterCount, parameters))
        << "Can't init the host";

    // init environment
    CHECK(tao_env_->EnvInit(PLATFORMTYPELINUXAPP, "bootstrap_files",
                            "www.manferdelli.com", directory, tao_host_.get(),
                            0, NULL)) << "Can't init the environment";
  }
  catch (const char * err) {
    LOG(ERROR) << "Error in initializing the legacy tao: " << err;
    tao_env_->EnvClose();
    tao_host_->HostClose();
    return false;
  }

  return true;
}

bool LegacyTao::getSecret(ScopedSafeString *secret) {
  CHECK_NOTNULL(secret);
  CHECK(tao_env_->m_myMeasurementValid)
      << "Can't create or unseal secrets due to invalid measurement";
  int size = SecretSize;
  FilePath fp(secret_path_);
  if (!PathExists(fp)) {
    // generate a random value for the key and seal it, writing the result
    // into this file
    RandImpl *rand = CryptoFactory::Rand();
    CHECK(rand->RandBytes(SecretSize, secret->get()))
        << "Could not generate a random secret to seal";

    // seal and save
    int sealed_size = SealedSize;
    scoped_array<unsigned char> sealed_secret(new unsigned char[sealed_size]);

    // this is safe, since the 4th argument is only read, despite not having
    // a const annotation
    byte *secret_data = reinterpret_cast<unsigned char *>(
        const_cast<char *>(secret->get()->data()));
    CHECK(
        tao_env_->Seal(tao_env_->m_myMeasurementSize, tao_env_->m_myMeasurement,
                       size, secret_data, &sealed_size, sealed_secret.get()))
        << "Can't seal the secret";
    VLOG(2) << "Got a sealed secret of size " << sealed_size;

    ofstream out_file(secret_path_.c_str(), ofstream::out);
    out_file.write(reinterpret_cast<char *>(sealed_secret.get()), sealed_size);
    out_file.close();

    VLOG(1) << "Sealed the secret";
  } else {
    // get the existing key blob and unseal it using the Tao
    ifstream in_file(secret_path_.c_str(),
                     ifstream::in | ios::binary | ios::ate);
    int sealed_size = in_file.tellg();

    VLOG(2) << "Trying to read a secret of size " << sealed_size;
    scoped_array<unsigned char> sealed_secret(new unsigned char[sealed_size]);

    // rewind to beginning of the file to read it
    in_file.seekg(0, ios::beg);
    in_file.read(reinterpret_cast<char *>(sealed_secret.get()), sealed_size);
    VLOG(1) << "Read the file";
    // a temporary ScopedSafeString to hold extra bytes until we know the
    // actual size of the sealed key
    scoped_array<unsigned char> temp_secret(new unsigned char[size]);
    CHECK(tao_env_->Unseal(tao_env_->m_myMeasurementSize,
                           tao_env_->m_myMeasurement, sealed_size,
                           sealed_secret.get(), &size, temp_secret.get()))
        << "Can't unseal the secret";
    secret->get()->assign(reinterpret_cast<char *>(temp_secret.get()), size);
    // TODO(tmroeder): Make this part of the destructor of the scoped_array
    memset(temp_secret.get(), 0, size);
    VLOG(2) << "Unsealed a secret of size " << size;
  }

  return true;
}

// TODO(tmroeder): combine this function and createKey by taking in the key type
// and purpose and writer.
bool LegacyTao::createPublicKey(Encrypter *crypter) {
  FilePath fp(pk_path_);
  scoped_ptr<KeysetWriter> writer(
      new KeysetEncryptedJSONFileWriter(fp, crypter));

  CHECK_NOTNULL(writer.get());
  scoped_ptr<Keyset> k(new Keyset());
  k->AddObserver(writer.get());
  k->set_encrypted(true);

  KeyType::Type key_type = KeyType::ECDSA_PRIV;
  KeyPurpose::Type key_purpose = KeyPurpose::SIGN_AND_VERIFY;
  KeysetMetadata *metadata = nullptr;
  metadata =
      new KeysetMetadata("legacy_tao_pk", key_type, key_purpose, true, 1);
  CHECK_NOTNULL(metadata);
  k->set_metadata(metadata);
  k->GenerateDefaultKeySize(KeyStatus::PRIMARY);

  signer_.reset(new Signer(k.release()));

  return true;
}

bool LegacyTao::createKey(const string &secret) {
  FilePath fp(key_path_);
  scoped_ptr<KeysetWriter> writer(new KeysetPBEJSONFileWriter(fp, secret));
  CHECK_NOTNULL(writer.get());

  scoped_ptr<Keyset> k(new Keyset());

  k->AddObserver(writer.get());
  k->set_encrypted(true);

  KeyType::Type key_type = KeyType::AES;
  KeyPurpose::Type key_purpose = KeyPurpose::DECRYPT_AND_ENCRYPT;
  KeysetMetadata *metadata = nullptr;
  metadata = new KeysetMetadata("legacy_tao", key_type, key_purpose, true, 1);
  CHECK_NOTNULL(metadata);

  k->set_metadata(metadata);
  k->GenerateDefaultKeySize(KeyStatus::PRIMARY);

  crypter_.reset(new Crypter(k.release()));
  return true;
}

bool LegacyTao::Destroy() { return true; }

bool LegacyTao::StartHostedProgram(const string &path, int argc, char **argv) {
  if (!child_hash_.empty()) {
    LOG(ERROR)
        << "Cannot start a second program under the legacy tao bootstrap";
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

  // create a pipe on which the child can communicate with the Tao
  int pipedown[2];
  int pipeup[2];

  if (pipe(pipedown) != 0) {
    LOG(ERROR) << "Could not create the downward pipe";
    return false;
  }

  if (pipe(pipeup) != 0) {
    LOG(ERROR) << "Could not create the upward pipe";
    return false;
  }

  // TODO(tmroeder): replace fork with clone
  int child_pid = fork();
  if (child_pid == -1) {
    LOG(ERROR) << "Could not fork";
    return false;
  }

  if (child_pid == 0) {
    // child process; exec with the read end of pipedown and the write end of
    // pipeup
    close(pipedown[1]);
    close(pipeup[0]);

    scoped_array<char *> new_argv(new char *[argc + 3]);

    for (int i = 0; i < argc; i++) {
      new_argv[i] = argv[i];
    }

    stringstream pread_buf;
    pread_buf << pipedown[0];
    string pread = pread_buf.str();
    scoped_array<char> pr(new char[pread.size() + 1]);
    size_t len = pread.copy(pr.get(), pread.size());
    pr[len] = '\0';

    stringstream pwrite_buf;
    pwrite_buf << pipeup[1];
    string pwrite = pwrite_buf.str();
    scoped_array<char> pw(new char[pwrite.size() + 1]);
    len = pwrite.copy(pw.get(), pwrite.size());
    pw[len] = '\0';

    new_argv[argc] = pr.get();
    new_argv[argc + 1] = pw.get();
    new_argv[argc + 2] = NULL;

    int rv = execv(path.c_str(), new_argv.get());
    if (rv == -1) {
      LOG(ERROR) << "Could not exec " << path;
      return false;
    }
  } else {
    close(pipedown[0]);
    close(pipeup[1]);

    child_fds_[0] = pipeup[0];
    child_fds_[1] = pipedown[1];
    child_hash_.assign(serialized_digest);
    PipeTaoChannel ptc(child_fds_);
    bool rv = ptc.Listen(this);
    if (!rv) {
      LOG(ERROR) << "Listening failed";
    }

    return rv;
  }

  return true;
}

bool LegacyTao::GetRandomBytes(size_t size, string *bytes) const {
  // just ask keyczar for random bytes, which will ask OpenSSL in turn
  RandImpl *rand = CryptoFactory::Rand();
  if (!rand->RandBytes(size, bytes)) {
    LOG(ERROR) << "Could not generate a random secret to seal";
    return false;
  }

  return true;
}

bool LegacyTao::Seal(const string &data, string *sealed) const {
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

bool LegacyTao::Unseal(const string &sealed, string *data) const {
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

bool LegacyTao::Attest(const string &data, string *attestation) const {
  if (child_hash_.empty()) {
    LOG(ERROR) << "Cannot create an attestation when there is no child process";
    return false;
  }

  if (!attestation) {
    LOG(ERROR) << "attestation was null";
    return false;
  }

  Attestation a;
  time_t cur_time;
  time(&cur_time);

  a.set_time(cur_time);
  a.set_data(data);
  a.set_hash_alg("SHA256");
  a.set_hash(child_hash_);

  string serialized_attestation;
  if (!a.SerializeToString(&serialized_attestation)) {
    LOG(ERROR) << "Could not serialize the attestation";
    return false;
  }

  string signature;
  if (!signer_->Sign(serialized_attestation, &signature)) {
    LOG(ERROR) << "Could not sign the attestation";
    return false;
  }

  SignedAttestation sa;
  sa.set_serialized_attestation(serialized_attestation);
  sa.set_signature(signature);

  // attach evidence:
  // 1. public key of the signer
  // 2. signature on public key of the signer by the legacy tao key
  // 3. certificate for the legacy tao key

  KeyczarPublicKey kpk;
  if (!SerializePublicKey(*signer_, &kpk)) {
    LOG(ERROR) << "Could not serialize the public key for signing";
    return false;
  }
  
  string *pub_key = sa.add_evidence();
  if (!kpk.SerializeToString(pub_key)) {
    LOG(ERROR) << "Could not serialize the KeyczarPublicKey to a string";
    return false;
  }
  
  // sign this key with our public key
  string *legacy_sig = sa.add_evidence();
  if (!SignWithLegacyKey(
			 *reinterpret_cast<RSAKey*>(tao_env_->m_privateKey),
			 *pub_key,
			 legacy_sig)) {
    LOG(ERROR) << "Could not sign our public key with the legacy public key";
    return false;
  }

  // add the certificate signed by the policy private key
  string *host_cert = sa.add_evidence();
  host_cert->assign(tao_env_->m_myCertificate, tao_env_->m_myCertificateSize);
  
  if (!sa.SerializeToString(attestation)) {
    LOG(ERROR) << "Could not serialize the SignedAttestation";
    return false;
  }

  return true;
}

bool LegacyTao::VerifyAttestation(const string &data, const string &attestation) const {
  SignedAttestation sa;
  if (!sa.ParseFromString(attestation)) {
    LOG(ERROR) << "Could not deserialize a SignedAttestation";
    return false;
  }

  // extract the public key used for signing and verify it
  int evidence_count = sa.evidence_size();
  if (evidence_count < 3) {
    LOG(ERROR) << "Not enough evidence to verify the attestation";
    return false;
  }

  if (evidence_count > 3) {
    LOG(ERROR) << "Too much evidence for the LegacyTao!";
    return false;
  }

  const string &serialized_pk = sa.evidence(0);
  KeyczarPublicKey kpk;
  if (!kpk.ParseFromString(serialized_pk)) {
    LOG(ERROR) << "Could not get a public key from the first evidence string";
    return false;
  }

  Keyset *keyset = nullptr;
  if (!DeserializePublicKey(kpk, &keyset)) {
    LOG(ERROR) << "Could not deserialize the public key from the first evidence string";
    return false;
  }

  scoped_ptr<Verifier> verifier(new Verifier(keyset));
  if (verifier.get() == nullptr) {
    LOG(ERROR) << "Could not construct a verifier from the deserialized public key";
    return false;
  }

  verifier->set_encoding(Keyczar::NO_ENCODING);

  if (!verifier->Verify(sa.serialized_attestation(), sa.signature())) {
    LOG(ERROR) << "The signature for the serialized attestation did not pass "
                  "verification";
    return false;
  }

  // now check the signature on the serialized verifier
  const string &legacy_sig = sa.evidence(1);
  const string &legacy_cert = sa.evidence(2);

  // first check the cert and extract the public key
  scoped_ptr<PrincipalCert> pc(new PrincipalCert());
  if (!pc->init(legacy_cert.data())) {
    LOG(ERROR) << "Could not create a cert from the third evidence string";
    return false;
  }

  if (!pc->parsePrincipalCertElements()) {
    LOG(ERROR) << "Could not finish parsing the certificate";
    return false;
  }

  // set up a chain to verify
  int chain_types[2] = {PRINCIPALCERT, EMBEDDEDPOLICYPRINCIPAL};
  RSAKey *legacy_policy_key = reinterpret_cast<RSAKey *>(legacy_policy_cert_->getSubjectKeyInfo());
  void *chain_objects[2] = {pc.get(), legacy_policy_key};
  if (VerifyChain(*legacy_policy_key, "", NULL, 2, chain_types, chain_objects) < 0) {
    LOG(ERROR) << "The certificate in the evidence did not pass verification";
    return false;
  }

  // now extract the RSAKey from the certificate and verify the
  // signature on the serialized keyczar public key
  RSAKey *inner_key = reinterpret_cast<RSAKey*>(pc->getSubjectKeyInfo());
  if (!VerifyWithLegacyKey(*inner_key, serialized_pk, legacy_sig)) {
    LOG(ERROR) << "The legacy signature did not pass verification";
    return false;
  }

  // at this point, all the signatures match, so deserialize and check
  // the Attestation itself

  Attestation a;
  if (!a.ParseFromString(sa.serialized_attestation())) {
    LOG(ERROR)
        << "Could not parse an Attestation from the serialized attestation";
    return false;
  }

  // check that the time isn't too far in the past
  time_t cur_time;
  time(&cur_time);

  time_t past_time = a.time();
  if (cur_time - past_time > AttestationTimeout) {
    LOG(ERROR) << "The attestation was too old";
    return false;
  }

  // check that this is a whitelisted program
  if (!auth_manager_->IsAuthorized(a.hash())) {
    LOG(ERROR) << "The attested program was not a whitelisted program";
    return false;
  }

  // and verify that the data matches the data in the attestation
  if (data.compare(a.data()) != 0) {
    LOG(ERROR) << "The supplied data does not match the data in the attestation";
    return false;
  }

  VLOG(1) << "The attestation passed verification";

  return true;
}

bool LegacyTao::SignWithLegacyKey(RSAKey &key, const string &data, string *signature) const {
  CHECK_NOTNULL(signature);
  Sha256 sha;
  unsigned char hash[SHA256_DIGESTSIZE_BYTES];
  unsigned char sig_value[1024];
  int size = 1024;

  sha.Init();
  sha.Update(reinterpret_cast<const unsigned char *>(data.data()), data.size());
  sha.Final();
  sha.GetDigest(hash);

  if(!RSASign(key, SHA256HASH, hash, &size, sig_value)) {
    LOG(ERROR) << "Could not compute the RSA signature for this hash value";
    return false;
  }

  signature->assign(const_cast<const char *>(reinterpret_cast<char *>(sig_value)), static_cast<size_t>(size));
  return true;
}

bool LegacyTao::VerifyWithLegacyKey(RSAKey &key, const string &data, const string &signature) const {
  Sha256 sha;
  unsigned char hash[SHA256_DIGESTSIZE_BYTES];
  
  sha.Init();
  sha.Update(reinterpret_cast<const unsigned char *>(data.data()), data.size());
  sha.Final();
  sha.GetDigest(hash);

  if (!RSAVerify(key, SHA256HASH, hash, const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(signature.data())))) {
    LOG(ERROR) << "Could not verify an RSA signature";
    return false;
  }

  return true;
}
}  // namespace cloudproxy
