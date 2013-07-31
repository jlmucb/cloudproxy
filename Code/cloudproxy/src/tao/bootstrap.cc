#include "bootstrap.h"

#include <keyczar/crypto_factory.h>
#include <keyczar/rw/keyset_file_reader.h>
#include <keyczar/rw/keyset_file_writer.h>
#include <keyczar/base/file_path.h>
#include <keyczar/base/file_util.h>
#include <glog/logging.h>

// minimal amount of code needed from old CloudProxy implementation to bootstrap
// into a new one
#include <jlmcrypto.h>
#include <keys.h>
#include <logging.h>
#include "policyCert.inc"
#include "whitelist.pb.h"

#include <fstream>

using std::ifstream;
using std::ofstream;

namespace cloudproxy {

Bootstrap::Bootstrap(const string &secret_path, const string &directory,
		     const string &key_path)
  : secret_path_(secret_path),
    directory_(directory),
    key_path_(key_path),
    tao_host_(new taoHostServices()),
    tao_env_(new taoEnvironment()),
    keyset_(new keyczar::Keyset()),
    key_(nullptr),
    child_fd_(-1) {
  // leave setup for Init
}

bool Bootstrap::Init() {
    // initialize jlmcrypto
    CHECK(initAllCrypto()) << "Could not initialize jlmcrypto";

    CHECK(initTao()) << "Could not initialize the Tao";
    VLOG(1) << "Initialized the Tao";

    // only keep the secret for the duration of this method:
    // long enough to unlock or create a sealed encryption key
    keyczar::base::ScopedSafeString secret(new string());
    CHECK(getSecret(&secret))
        << "Could not generate (and seal) or unseal the secret using the Tao";
    VLOG(1) << "Got the secret";

    // now get our keyczar::Verifier HMAC key that was encrypted using this
    // secret or generate and encrypt a new one
    FilePath fp(key_path_);
    if (!keyczar::base::PathExists(fp)) {
      CHECK(keyczar::base::CreateDirectory(fp))
        << "Could not create the key directory " << key_path_;

      // create a new keyset
      CHECK(createKey(*secret)) << "Could not create keyset";
    } else {
      // read the keyset from the encrypted directory
      scoped_ptr<keyczar::rw::KeysetReader> reader(
          new keyczar::rw::KeysetPBEJSONFileReader(fp, *secret));
      keyset.reset(keyczar::Keyset::Read(*reader, true));
      CHECK_NOTNULL(keyset.get());
    }

    key_ = keyset_->primary_key();
    CHECK_NOTNULL(key_);

    VLOG(1) << "Finished bootstrap initialization successfully";
    return true;
}

bool Bootstrap::initTao() {
  const char *directory = directory_.c_str();
  const char **parameters = &directory;
  int parameterCount = 1;

  try {
    // init host
    CHECK(tao_host_->HostInit(PLATFORMTYPELINUX, parameterCount, parameters))
        << "Can't init the host";

    // init environment
    CHECK(tao_env_->EnvInit(PLATFORMTYPELINUXAPP, "bootstrap_files",
                          "www.manferdelli.com", directory, tao_host_, 0, NULL))
        << "Can't init the environment";
  }
  catch (const char * err) {
    LOG(ERROR) << "Error in initializing the legacy tao: " << err;
    tao_env_->EnvClose();
    tao_host_->HostClose();
    return false;
  }

  return true;
}

bool Bootstrap::getSecret(keyczar::base::ScopedSafeString *secret) {
  CHECK_NOTNULL(secret);
  CHECK(tao_env_->m_myMeasurementValid)
      << "Can't create or unseal secrets due to invalid measurement";
  int size = secret_size;
  FilePath fp(secret_path_);
  if (!keyczar::PathExists(fp))
    // generate a random value for the key and seal it, writing the result
    // into this file
    keyczar::RandImpl *rand = keyczar::CryptoFactory::Rand();
    CHECK(rand->RandBytes(SecretSize, secret->get()))
        << "Could not generate a random secret to seal";

    // seal and save
    int sealed_size = SealedSize;
    scoped_array<unsigned char> sealed_secret(new unsigned char[sealed_size]);

    // this is safe, since the 4th argument is only read, despite not having
    // a const annotation
    byte *secret_data = reinterpret_cast<unsigned char *>(
        const_cast<char *>(secret.get()->data()));
    CHECK(tao_env_->Seal(tao_env_->m_myMeasurementSize,
			 tao_env_->m_myMeasurement,
			 size, secret_data, &sealed_size, sealed_secret.get()))
        << "Can't seal the secret";
    VLOG(2) << "Got a sealed secret of size " << sealed_size;

    ofstream out_file(secret_path_.c_str(), ofstream::out);
    out_file.write(reinterpret_cast<char *>(sealed_secret.get()), sealed_size);
    out_file.close();

    VLOG(1) << "Sealed the secret";
  } else {
    // get the existing key blob and unseal it using the Tao
    int sealed_size = st.st_size;
    VLOG(2) << "Trying to read a secret of size " << sealed_size;
    scoped_array<unsigned char> sealed_secret(new unsigned char[sealed_size]);

    ifstream in_file(secret_path_.c_str(), ifstream::in);
    in_file.read(reinterpret_cast<char *>(sealed_secret.get()), sealed_size);
    VLOG(1) << "Read the file";
    // a temporary ScopedSafeString to hold extra bytes until we know the
    // actual size of the sealed key
    scoped_array<unsigned char> temp_secret(new unsigned char[size]);
    CHECK(tao_env_->Unseal(tao_env_->m_myMeasurementSize,
			   tao_env_->m_myMeasurement,
			   sealed_size, sealed_secret.get(), &size,
			   temp_secret.get())) << "Can't unseal the secret";
    secret->get()->assign(reinterpret_cast<char *>(temp_secret.get()), size);
    // TODO(tmroeder): Make this part of the destructor of the scoped_array
    memset(temp_secret.get(), 0, size);
    VLOG(2) << "Unsealed a secret of size " << size;
  }

  return true;
}

bool Bootstrap::createKey(const string &secret) {
  FilePath fp(key_path_);
  scoped_ptr<keyczar::rw::KeysetWriter> writer(
      new keyczar::rw::KeysetPBEJSONFileWriter(fp, secret));
  CHECK_NOTNULL(writer.get());

  keyset_->AddObserver(writer.get());
  keyset_->set_encrypted(true);

  keyczar::KeyType::Type key_type = keyczar::KeyType::AES;
  keyczar::KeyPurpose::Type key_purpose = keyczar::KeyPurpose::DECRYPT_AND_ENCRYPT;
  keyczar::KeysetMetadata *metadata = NULL;
  metadata = new keyczar::KeysetMetadata("bootstrap", key_type, key_purpose,
                                         true, 1);
  CHECK_NOTNULL(metadata);

  keyset_->set_metadata(metadata);
  keyset_->GenerateDefaultKeySize(keyczar::KeyStatus::PRIMARY);
  return true;
}
} // namespace cloudproxy
