#include "legacy_tao/legacy_tao.h"
#include "tao/attestation.pb.h"
#include "tao/hosted_programs.pb.h"
#include "tao/quote.pb.h"
#include "tao/pipe_tao_channel.h"

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
#include <keys.h>
#include <logging.h>
#include <policyCert.inc>

#include <fstream>
#include <sstream>

using tao::HostedProgram;
using tao::PipeTaoChannel;
using tao::SignedWhitelist;
using tao::Whitelist;

using keyczar::base::Base64WEncode;
using keyczar::Crypter;
using keyczar::CryptoFactory;
using keyczar::Encrypter;
using keyczar::Keyset;
using keyczar::KeysetMetadata;
using keyczar::KeyType;
using keyczar::KeyPurpose;
using keyczar::KeyStatus;
using keyczar::MessageDigestImpl;
using keyczar::RandImpl;
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
      whitelist_path_(whitelist_path),
      policy_pk_path_(policy_pk_path),
      tao_host_(new taoHostServices()),
      tao_env_(new taoEnvironment()),
      keyset_(new Keyset()),
      pk_keyset_(new Keyset()),
      key_(nullptr),
      pk_(nullptr),
      policy_pk_(nullptr),
      child_fd_(-1) {
  // leave setup for Init
}

bool LegacyTao::Init() {
  // load the public policy key
  policy_pk_.reset(Verifier::Read(policy_pk_path_.c_str()));
  CHECK_NOTNULL(policy_pk_.get());
  
  // load the whitelist file and check its signature
  ifstream whitelist(whitelist_path_);

  SignedWhitelist sw;
  sw.ParseFromIstream(&whitelist);
  CHECK(policy_pk_->Verify(sw.serialized_whitelist(), sw.signature()))
    << "The signature did not verify on the signed whitelist";

  Whitelist w;
  w.ParseFromString(sw.serialized_whitelist());
  for (auto &i : w.programs()) {
    CHECK(whitelist_.find(i.name()) == whitelist_.end())
      << "Can't add " << i.name() << " to the whitelist twice";
    whitelist_[i.name()] = i.hash();
  }

  // initialize jlmcrypto
  CHECK(initAllCrypto()) << "Could not initialize jlmcrypto";

  CHECK(initTao()) << "Could not initialize the Tao";
  VLOG(1) << "Initialized the Tao";

  // only keep the secret for the duration of this method:
  // long enough to unlock or create a sealed encryption key
  ScopedSafeString secret(new string());
  CHECK(getSecret(&secret))
      << "Could not generate (and seal) or unseal the secret using the Tao";
  VLOG(1) << "Got the secret";

  // now get our Crypter key that was encrypted using this
  // secret or generate and encrypt a new one
  FilePath fp(key_path_);
  if (!PathExists(fp)) {
    CHECK(CreateDirectory(fp)) << "Could not create the key directory "
                               << key_path_;

    // create a new keyset
    CHECK(createKey(*secret)) << "Could not create keyset";
  } else {
    // read the keyset from the encrypted directory
    scoped_ptr<KeysetReader> reader(new KeysetPBEJSONFileReader(fp, *secret));
    keyset_.reset(Keyset::Read(*reader, true));
    CHECK_NOTNULL(keyset_.get());
  }

  key_ = keyset_->primary_key();
  CHECK_NOTNULL(key_);

  // get a public-private key pair from the Tao key (either create and seal or
  // just unseal it).

  // First we need another copy of the crypter to give to the encrypted file
  // reader. By this point, however, there should be a copy on disk, so we can
  // use the secret again to get it.
  scoped_ptr<KeysetReader> crypter_reader(
      new KeysetPBEJSONFileReader(fp, *secret));
  scoped_ptr<Crypter> crypter(new Crypter(Keyset::Read(*crypter_reader, true)));

  FilePath pk_fp(pk_path_);
  if (!PathExists(pk_fp)) {
    CHECK(CreateDirectory(pk_fp))
        << "Could not create the directory for a public-private key pair";
    CHECK(createPublicKey(crypter.release()))
        << "Could not create the publick key";
  } else {
    scoped_ptr<KeysetReader> reader(
        new KeysetEncryptedJSONFileReader(pk_fp, crypter.release()));
    pk_keyset_.reset(Keyset::Read(*reader, true));
    CHECK_NOTNULL(pk_keyset_.get());
  }

  pk_ = pk_keyset_->primary_key();

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

  pk_keyset_->AddObserver(writer.get());
  pk_keyset_->set_encrypted(true);

  KeyType::Type key_type = KeyType::ECDSA_PRIV;
  KeyPurpose::Type key_purpose = KeyPurpose::SIGN_AND_VERIFY;
  KeysetMetadata *metadata = nullptr;
  metadata =
      new KeysetMetadata("legacy_tao_pk", key_type, key_purpose, true, 1);
  CHECK_NOTNULL(metadata);
  pk_keyset_->set_metadata(metadata);
  pk_keyset_->GenerateDefaultKeySize(KeyStatus::PRIMARY);

  return true;
}

bool LegacyTao::createKey(const string &secret) {
  FilePath fp(key_path_);
  scoped_ptr<KeysetWriter> writer(new KeysetPBEJSONFileWriter(fp, secret));
  CHECK_NOTNULL(writer.get());

  keyset_->AddObserver(writer.get());
  keyset_->set_encrypted(true);

  KeyType::Type key_type = KeyType::AES;
  KeyPurpose::Type key_purpose = KeyPurpose::DECRYPT_AND_ENCRYPT;
  KeysetMetadata *metadata = nullptr;
  metadata = new KeysetMetadata("legacy_tao", key_type, key_purpose, true, 1);
  CHECK_NOTNULL(metadata);

  keyset_->set_metadata(metadata);
  keyset_->GenerateDefaultKeySize(KeyStatus::PRIMARY);
  return true;
}

bool LegacyTao::Destroy() { return true; }

bool LegacyTao::StartHostedProgram(const string &path, int argc, char **argv) {
  // first check to make sure that this program is authorized

  // TODO(tmroeder): get the final component of the path rather than
  // insisting that the path match exactly
  auto w = whitelist_.find(path);
  if (w == whitelist_.end()) 
    return false;

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
  
  // check that the digests match
  if (w->second.compare(serialized_digest) != 0) {
    LOG(ERROR) << "The digest stored for " << path << " is " << w->second
	       << "which does not match the computed digest "
	       << serialized_digest;
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

  int child_pid = fork();
  if (child_pid == -1) {
    LOG(ERROR) << "Could not fork";
    return false;
  }

  if (child_pid == 0) {
    // child process; exec with the read end of pipedown and the write end of pipeup
    close(pipedown[1]);
    close(pipeup[0]);

    scoped_array<char*> new_argv(new char*[argc + 3]);

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

    int rv = execv(path.c_str(), new_argv);
    if (rv == -1) {
      LOG(ERROR) << "Could not exec " << path;
      return false;
    }
  } else {
    // parent process: send message on downward pipe and receive message on upward pipe
    close(pipedown[0]);
    close(pipeup[1]);

    int fds[2];
    fds[0] = pipeup[0];
    fds[1] = pipedown[1];
    PipeTaoChannel ptc(fds);
    bool rv = ptc.Listen(this);
    if (!rv) {
      LOG(ERROR) << "Listening failed";
    }

    return rv;
  }

  return true;
}
  
bool LegacyTao::GetRandomBytes(size_t size, string *bytes) {
  // just ask keyczar for random bytes, which will ask OpenSSL in turn
  RandImpl *rand = CryptoFactory::Rand();
  if (!rand->RandBytes(size, bytes)) {
    LOG(ERROR) << "Could not generate a random secret to seal";
    return false;
  }
  
  return true;
}
  

bool LegacyTao::Seal(const string &data, string *sealed) {
  // encrypt it using our symmetric key
  if (!key_->Encrypt(data, sealed)) {
    LOG(ERROR) << "Could not seal the data";
    return false;
  }

  return true;
}

bool LegacyTao::Unseal(const string &sealed, string *data)  {
  // decrypt it using our symmetric key
  if (!key_->Decrypt(sealed, data)) {
    LOG(ERROR) << "Could not unseal the data";
    return false;
  }

  return true;
}
  
bool LegacyTao::Quote(const string &data, string *signature) {
  // TODO(tmroeder): implement this with tao::SignedQuote as the signature
  return false;
}

bool LegacyTao::VerifyQuote(const string &data, const string &signature) {
  // TODO(tmroeder): implement this with tao::SignedQuote as the signature
  return false;
}


bool LegacyTao::Attest(string *attestation) {
  // TOOD(tmroeder): get the current time and produce a signature
  return false;
}

bool LegacyTao::VerifyAttestation(const string &attestation) {
  // TODO(tmroeder): check that the time isn't too long ago (5 minutes?) and check the signature
  // TODO(tmroeder): make this signature depend on all lower levels of the Tao
  // Also need to make sure that we're checking that it's a trusted signature, *not* necessarily a signature from our key
  return false;
}
}  // namespace cloudproxy
