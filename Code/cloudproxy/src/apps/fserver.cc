//  File: fserver.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An example file server application using FileServer
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

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include "cloudproxy/file_server.h"
#include "tao/pipe_tao_channel.h"

#include <mutex>
#include <string>
#include <vector>

using std::mutex;
using std::string;
using std::vector;

using tao::PipeTaoChannel;
using tao::TaoChannel;

DEFINE_string(file_path, "file_server_files",
              "The path used by the file server to store files");
DEFINE_string(meta_path, "file_server_meta",
              "The path used by the file server to store metadata");
DEFINE_string(server_cert, "./openssl_keys/server/server.crt",
              "The PEM certificate for the server to use for TLS");
DEFINE_string(server_key, "./openssl_keys/server/server.key",
              "The private key file for the server for TLS");
DEFINE_string(server_password, "cpserver", "The password for the server key");
DEFINE_string(policy_key, "./policy_public_key", "The keyczar public"
                                                 " policy key");
DEFINE_string(pem_policy_key, "./openssl_keys/policy/policy.crt",
              "The PEM public policy cert");
DEFINE_string(acls, "./acls_sig",
              "A file containing a SignedACL signed by"
              " the public policy key (e.g., using sign_acls)");
DEFINE_string(server_enc_key, "./server_key", "A keyczar crypter"
                                              " directory");
DEFINE_string(whitelist_path, "./signed_whitelist",
              "The path to the signed whitelist");
DEFINE_string(address, "localhost", "The address to listen on");
DEFINE_int32(port, 11235, "The port to listen on");

vector<shared_ptr<mutex> > locks;

void locking_function(int mode, int n, const char *file, int line) {
  if (mode & CRYPTO_LOCK) {
    locks[n]->lock();
  } else {
    locks[n]->unlock();
  }
}

int main(int argc, char **argv) {
  // make sure protocol buffers is using the right version
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  google::ParseCommandLineFlags(&argc, &argv, true);

  FLAGS_alsologtostderr = true;
  google::InitGoogleLogging(argv[0]);

  // try to establish a channel with the Tao
  int fds[2];
  CHECK(PipeTaoChannel::ExtractPipes(&argc, &argv, fds))
      << "Could not extract pipes from the end of the argument list";
  scoped_ptr<TaoChannel> channel(new PipeTaoChannel(fds));
  CHECK_NOTNULL(channel.get());

  // initialize OpenSSL
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();
  SSL_library_init();

  // set up locking in OpenSSL
  int lock_count = CRYPTO_num_locks();
  locks.resize(lock_count);
  for (int i = 0; i < lock_count; i++) {
    locks[i].reset(new mutex());
  }
  CRYPTO_set_locking_callback(locking_function);

  cloudproxy::FileServer fs(
      FLAGS_file_path, FLAGS_meta_path, FLAGS_server_cert, FLAGS_server_key,
      FLAGS_server_password, FLAGS_policy_key, FLAGS_pem_policy_key, FLAGS_acls,
      FLAGS_whitelist_path, FLAGS_server_enc_key, FLAGS_address, FLAGS_port);

  CHECK(fs.Listen(*channel)) << "Could not listen for client connections";
  return 0;
}
