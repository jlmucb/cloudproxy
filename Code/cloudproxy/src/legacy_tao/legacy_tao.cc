#include "legacy_tao/legacy_tao.h"

#include <keyczar/rw/keyset_file_reader.h>
#include <keyczar/rw/keyset_file_writer.h>
#include <keyczar/rw/keyset_encrypted_file_reader.h>
#include <keyczar/rw/keyset_encrypted_file_writer.h>
#include <keyczar/base/file_path.h>
#include <keyczar/base/file_util.h>
#include <glog/logging.h>

// minimal amount of code needed from the old CloudProxy implementation to
// bootstrap into a new one
#include "jlmcrypto.h"
#include "keys.h"
#include "logging.h"
#include "policyCert.inc"

#include <fstream>

using keyczar::Crypter;
using keyczar::CryptoFactory;
using keyczar::Encrypter;
using keyczar::Keyset;
using keyczar::KeysetMetadata;
using keyczar::KeyType;
using keyczar::KeyPurpose;
using keyczar::KeyStatus;
using keyczar::RandImpl;

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

namespace legacy_tao {

LegacyTao::LegacyTao(const string &secret_path, const string &directory,
                     const string &key_path, const string &pk_path)
    : secret_path_(secret_path),
      directory_(directory),
      key_path_(key_path),
      pk_path_(pk_path),
      tao_host_(new taoHostServices()),
      tao_env_(new taoEnvironment()),
      keyset_(new Keyset()),
      pk_keyset_(new Keyset()),
      key_(nullptr),
      child_fd_(-1) {
  // leave setup for Init
}

bool LegacyTao::Init() {
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

bool LegacyTao::Destroy() { return false; }

bool LegacyTao::StartHostedProgram(const string &path, int argc, char **argv) {
  return false;
}

bool LegacyTao::GetRandomBytes(size_t size, string *bytes) { return false; }

bool LegacyTao::Seal(const string &data, string *sealed) { return false; }

bool LegacyTao::Unseal(const string &sealed, string *data) { return false; }

bool LegacyTao::Attest(const string &data, string *attested) { return false; }

bool LegacyTao::Verify(const string &attested) { return false; }
}  // namespace cloudproxy
