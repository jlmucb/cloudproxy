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
#include <glog/logging.h>
#include <gflags/gflags.h>

// minimal amount of code needed from old CloudProxy implementation to bootstrap
// into a new one
#include <logging.h>
#include <keys.h>
#include <tao.h>

#include <fstream>
#include <string>

using std::ifstream;
using std::ofstream;
using std::string;

DEFINE_string(key_path, "", "The path to the TPM-sealed key for this binary");
DEFINE_string(directory, "", "The directory to use for Tao initialization");

const int AesBlockSize = 16;
const int Sha256Size = 32;
const int SecretSize = 64;

// Initialize the tao infrastructure
bool initTao(const char* configDirectory, taoHostServices *taoHost,
             taoEnvironment *taoEnv);

// Unseal a secret or create and seal a secret using the Tao
bool initKeys(taoHostServices *taoHost, taoEnvironment *taoEnv,
              keyczar::base::ScopedSafeString &secret, int secret_size);

int main(int argc, char** argv) {
    google::ParseCommandLineFlags(&argc, &argv, true);

    bool start_measured = false;
    initLog(NULL);

    // make sure we have a location for the sealed key
    CHECK(!FLAGS_key_path.empty()) << "Must supply a path for the sealed key";
    CHECK(!FLAGS_directory.empty()) << "Must supply a directory for the Tao";

    if (argc > 1) {
        for (int i = 0; i < argc; i++) {
            if (strcmp(argv[i], "-initProg") == 0) {
                start_measured = true;
            }
        }
    }

    // request a measured start
    if (start_measured) {
        if (!startMeAsMeasuredProgram(argc, argv)) {
            return 1;
        }
        return 0;
    }

    try {
        taoHostServices taoHost;
        taoEnvironment taoEnv;
        CHECK(initTao(FLAGS_directory.c_str(), &taoHost, &taoEnv))
          << "Could not initialize the Tao";

        keyczar::base::ScopedSafeString secret(new string());
        CHECK(initKeys(&taoHost, &taoEnv, secret, SecretSize))
          << "Could not initialize keys using the Tao";

        LOG(INFO) << "Finished the basic key setup";

        closeLog();

    } 
    catch (const char * err) {
        LOG(ERROR) << "Execution failed with error " << err;
        return 1;
    }

    return 0;
}

bool initTao(const char* configDirectory, taoHostServices* taoHost,
          taoEnvironment* taoEnv) {
    CHECK(configDirectory) << "null configDirectory";
    CHECK(taoHost) << "null taoHost";
    CHECK(taoEnv) << "null taoEnv";
    const char* directory = configDirectory;
    const char** parameters = &directory;
    int parameterCount = 1;

    try {
        // init host
        CHECK(taoHost->HostInit(PLATFORMTYPELINUX, parameterCount, parameters))
          << "Can't init the host";

        // init environment
        CHECK(taoEnv->EnvInit(PLATFORMTYPELINUXAPP, "bootstrap",
                              "www.manferdelli.com",
                              directory, taoHost, 0, NULL)) 
          << "Can't init the environment";
    } catch (const char *err) {
        LOG(ERROR) << "Error: " << err;
        taoEnv->EnvClose();
        taoHost->HostClose();
        return false;
    }

    return true;
}

bool initKeys(taoHostServices *taoHost, taoEnvironment *taoEnv,
              keyczar::base::ScopedSafeString &secret, int secret_size) {
   
    CHECK(taoEnv->m_myMeasurementValid)
      << "Can't init keys due to invalid measurement";

    struct stat st;
    if (stat(FLAGS_key_path.c_str(), &st) != 0) {
        // generate a random value for the key and seal it, writing the result
        // into this file
        keyczar::RandImpl *rand = keyczar::CryptoFactory::Rand();
        CHECK(rand->RandBytes(secret_size, secret.get()))
          << "Could not generate a random secret to seal";

        // seal and save

        // this is a CBC encryption with HMAC-SHA256 at the end, so it will take
        // up at most secret_size + 2 * AesBlockSize + Sha256Size.
        // I wish there were an API call in the Tao to tell me what this size
        // should be. 
        int sealed_size = secret_size + 2 * AesBlockSize + Sha256Size;
        scoped_array<unsigned char> sealed_secret(
          new unsigned char[sealed_size]);

        // this is safe, since the 4th argument is only read, despite not having
        // a const annotation
        byte *secret_data = reinterpret_cast<unsigned char *>(
          const_cast<char *>(secret.get()->data()));
        CHECK(taoEnv->Seal(taoEnv->m_myMeasurementSize,
                           taoEnv->m_myMeasurement, secret_size,
                           secret_data, &sealed_size,
                           sealed_secret.get()))
          << "Can't seal the secret";

        ofstream out_file(FLAGS_key_path.c_str(), ofstream::out);
        out_file.write(reinterpret_cast<char *>(sealed_secret.get()), sealed_size);
        out_file.close();
    } else {
        // get the existing key blob and unseal it using the Tao
        int sealed_size = st.st_size;
        scoped_array<unsigned char> sealed_secret(
          new unsigned char[sealed_size]);
        
        ifstream in_file(FLAGS_key_path.c_str(), ifstream::in);
        in_file.read(reinterpret_cast<char *>(sealed_secret.get()), sealed_size);

        // a temporary ScopedSafeString to hold extra bytes until we know the
        // actual size of the sealed key
        secret.get()->reserve(secret_size);
        unsigned char *mutable_secret = reinterpret_cast<unsigned char *>(
          keyczar::base::string_as_array(secret.get()));
        CHECK(taoEnv->Unseal(taoEnv->m_myMeasurementSize,
                             taoEnv->m_myMeasurement, sealed_size,
                             sealed_secret.get(), &secret_size,
                             mutable_secret))
          << "Can't unseal the secret";
    }

    return true;
}
