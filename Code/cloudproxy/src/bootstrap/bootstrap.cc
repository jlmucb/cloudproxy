//  File: bootstrap.cpp
//      Tom Roeder
//
//  Description: A simple client that initializes the Tao then gets a signed
//  list and path to a binary as input. It checks the signature on the list,
//  checks the binary against its hash on the list, and starts the requested
//  application.
//
//  Copyright (c) 2013, Google Inc.  All rights reserved.
//
// Use, duplication and disclosure of this file and derived works of
// this file are subject to and licensed under the Apache License dated
// January, 2004, (the "License").  This License is contained in the
// top level directory originally provided with the CloudProxy Project.
// Your right to use or distribute this file, or derived works thereof,
// is subject to your being bound by those terms and your use indicates
// consent to those terms.
//
// If you distribute this file (or portions derived therefrom), you must
// include License in or with the file and, in the event you do not include
// the entire License in the file, the file must contain a reference
// to the location of the License.

// ------------------------------------------------------------------------

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <keyczar/keyczar.h>
#include <keyczar/crypto_factory.h>
#include <keyczar/rw/keyset_file_reader.h>
#include <keyczar/rw/keyset_file_writer.h>
#include <keyczar/base/file_path.h>
#include <keyczar/base/file_util.h>
#include <glog/logging.h>
#include <gflags/gflags.h>

// minimal amount of code needed from old CloudProxy implementation to bootstrap
// into a new one
#include <jlmcrypto.h>
#include <keys.h>
#include <logging.h>
#include <tao.h>
#include "policyCert.inc"

#include <fstream>
#include <string>

using std::ifstream;
using std::ofstream;
using std::string;

DEFINE_string(key_path, "bootstrap_key",
              "The path to the TPM-sealed key for this binary");
DEFINE_string(directory, "/home/jlm/jlmcrypt",
              "The directory to use for Tao initialization");
DEFINE_string(hmac_key_path, "bootstrap_hmac_key",
              "An encrypted HMAC keyczar directory");
DEFINE_bool(initProg, false, "A flag that indicates measured boot");

const int AesBlockSize = 16;
const int Sha256Size = 32;
const int SecretSize = 64;
const int SealedSize = 160;  // until the Tao provides a way to get this info

// Initialize the tao infrastructure
bool initTao(const char *configDirectory, taoHostServices *taoHost,
             taoEnvironment *taoEnv);

// Unseal a secret or create and seal a secret using the Tao
bool getSecret(taoHostServices *taoHost, taoEnvironment *taoEnv,
               keyczar::base::ScopedSafeString &secret, int secret_size);

// create a new key encrypted with a given secret, and put the key into the
// supplied keyset
bool createKey(const string &secret, keyczar::Keyset *keyset);

int main(int argc, char **argv) {

  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InstallFailureSignalHandler();

  initLog(NULL);

  bool start_measured = false;

  if (argc > 1) {
    for (int i = 0; i < argc; i++) {
      if (strcmp(argv[i], "-initProg") == 0) {
        start_measured = true;
      }
    }
  }

  // set up a logging directory depending on whether or not this is measured
  if (start_measured) {
    FLAGS_log_dir = "b_orig";
  } else {
    FLAGS_log_dir = "b_meas";
  }

  google::InitGoogleLogging(argv[0]);

  // request a measured start
  if (start_measured) {
    if (!startMeAsMeasuredProgram(argc, argv)) {
      return 1;
    }
    return 0;
  }
  initLog("bootstrap.log");

  LOG(INFO) << "Measured program starting";
  try {
    // initialize jlmcrypto
    CHECK(initAllCrypto()) << "Could not initialize jlmcrypto";

    taoHostServices taoHost;
    taoEnvironment taoEnv;
    CHECK(initTao(FLAGS_directory.c_str(), &taoHost, &taoEnv))
        << "Could not initialize the Tao";
    fprintf(g_logFile, "Initialized the Tao\n");
    fflush(g_logFile);
    LOG(INFO) << "Initialized the Tao";

    keyczar::base::ScopedSafeString secret(new string());
    CHECK(getSecret(&taoHost, &taoEnv, secret, SecretSize))
        << "Could not generate (and seal) or unseal the secret using the Tao";
    LOG(INFO) << "Got the secret";
    fprintf(g_logFile, "Got the secret\n");
    fflush(g_logFile);

    // now get our keyczar::Verifier HMAC key that was encrypted using this
    // secret or generate and encrypt a new one
    scoped_ptr<keyczar::Keyset> keyset(new keyczar::Keyset());
    FilePath fp(FLAGS_hmac_key_path);
    if (!keyczar::base::PathExists(fp)) {
      CHECK(keyczar::base::CreateDirectory(fp))
        << "Could not create the key directory " << FLAGS_hmac_key_path;

      // create a new keyset
      CHECK(createKey(*secret, keyset.get())) << "Could not create keyset";
      fprintf(g_logFile, "Created a new keyset\n");
      fflush(g_logFile);
    } else {
      // read the keyset from the encrypted directory
      scoped_ptr<keyczar::rw::KeysetReader> reader(
          new keyczar::rw::KeysetPBEJSONFileReader(fp, *secret));
      keyset.reset(keyczar::Keyset::Read(*reader, true));
      CHECK_NOTNULL(keyset.get());
      fprintf(g_logFile, "Recovered the previous keyset\n");
      fflush(g_logFile);
    }

    const keyczar::Key* hmac_key(keyset->primary_key());
    CHECK_NOTNULL(hmac_key);

    // IAH: get this to compile and see if it works

    LOG(INFO) << "Finished the basic key setup";

    closeLog();
  }
  catch (const char * err) {
    LOG(ERROR) << "Execution failed with error " << err;
    return 1;
  }

  return 0;
}

bool initTao(const char *configDirectory, taoHostServices *taoHost,
             taoEnvironment *taoEnv) {
  CHECK_NOTNULL(configDirectory);
  CHECK_NOTNULL(taoHost);
  CHECK(taoEnv) << "null taoEnv";
  const char *directory = configDirectory;
  const char **parameters = &directory;
  int parameterCount = 1;

  try {
    // init host
    CHECK(taoHost->HostInit(PLATFORMTYPELINUX, parameterCount, parameters))
        << "Can't init the host";

    // init environment
    CHECK(taoEnv->EnvInit(PLATFORMTYPELINUXAPP, "bootstrap_files",
                          "www.manferdelli.com", directory, taoHost, 0, NULL))
        << "Can't init the environment";
  }
  catch (const char * err) {
    LOG(ERROR) << "Error: " << err;
    taoEnv->EnvClose();
    taoHost->HostClose();
    return false;
  }

  return true;
}

bool getSecret(taoHostServices *taoHost, taoEnvironment *taoEnv,
               keyczar::base::ScopedSafeString &secret, int secret_size) {

  CHECK(taoEnv->m_myMeasurementValid)
      << "Can't init keys due to invalid measurement";
  int size = secret_size;
  struct stat st;
  if (stat(FLAGS_key_path.c_str(), &st) != 0) {
    // generate a random value for the key and seal it, writing the result
    // into this file
    keyczar::RandImpl *rand = keyczar::CryptoFactory::Rand();
    CHECK(rand->RandBytes(size, secret.get()))
        << "Could not generate a random secret to seal";

    // seal and save
    int sealed_size = SealedSize;
    scoped_array<unsigned char> sealed_secret(new unsigned char[sealed_size]);

    // this is safe, since the 4th argument is only read, despite not having
    // a const annotation
    byte *secret_data = reinterpret_cast<unsigned char *>(
        const_cast<char *>(secret.get()->data()));
    fprintf(g_logFile, "The measurement is %p\n", taoEnv->m_myMeasurement);
    fflush(g_logFile);
    CHECK(taoEnv->Seal(taoEnv->m_myMeasurementSize, taoEnv->m_myMeasurement,
                       size, secret_data, &sealed_size, sealed_secret.get()))
        << "Can't seal the secret";
    LOG(INFO) << "Got a sealed secret of size " << sealed_size;

    ofstream out_file(FLAGS_key_path.c_str(), ofstream::out);
    out_file.write(reinterpret_cast<char *>(sealed_secret.get()), sealed_size);
    out_file.close();

    LOG(INFO) << "Sealed the secret";
  } else {
    // get the existing key blob and unseal it using the Tao
    int sealed_size = st.st_size;
    LOG(INFO) << "Trying to read a secret of size " << sealed_size;
    scoped_array<unsigned char> sealed_secret(new unsigned char[sealed_size]);

    ifstream in_file(FLAGS_key_path.c_str(), ifstream::in);
    in_file.read(reinterpret_cast<char *>(sealed_secret.get()), sealed_size);
    LOG(INFO) << "Read the file";
    // a temporary ScopedSafeString to hold extra bytes until we know the
    // actual size of the sealed key
    scoped_array<unsigned char> temp_secret(new unsigned char[size]);
    fprintf(g_logFile, "The measurement is %p\n", taoEnv->m_myMeasurement);
    PrintBytes("Measurement: ", taoEnv->m_myMeasurement,
               taoEnv->m_myMeasurementSize);
    fflush(g_logFile);
    CHECK(taoEnv->Unseal(taoEnv->m_myMeasurementSize, taoEnv->m_myMeasurement,
                         sealed_size, sealed_secret.get(), &size,
                         temp_secret.get())) << "Can't unseal the secret";
    secret.get()->assign(reinterpret_cast<char *>(temp_secret.get()), size);
    // TODO(tmroeder): Make this part of the destructor of the scoped_array
    memset(temp_secret.get(), 0, size);
    LOG(INFO) << "Unsealed a secret of size " << size;
  }

  return true;
}

bool createKey(const string &secret, keyczar::Keyset *keyset) {
  CHECK_NOTNULL(keyset);

  FilePath fp(FLAGS_hmac_key_path);
  scoped_ptr<keyczar::rw::KeysetWriter> writer(
      new keyczar::rw::KeysetPBEJSONFileWriter(fp, secret));
  CHECK_NOTNULL(writer.get());

  keyset->AddObserver(writer.get());
  keyset->set_encrypted(true);

  keyczar::KeyType::Type key_type = keyczar::KeyType::HMAC;
  keyczar::KeyPurpose::Type key_purpose = keyczar::KeyPurpose::SIGN_AND_VERIFY;
  keyczar::KeysetMetadata *metadata = NULL;
  metadata = new keyczar::KeysetMetadata("bootstrap", key_type, key_purpose,
                                         true, 1);
  CHECK_NOTNULL(metadata);

  keyset->set_metadata(metadata);
  keyset->GenerateDefaultKeySize(keyczar::KeyStatus::PRIMARY);
  fprintf(g_logFile, "Finished generating the key\n");
  fflush(g_logFile);
  return true;
}
