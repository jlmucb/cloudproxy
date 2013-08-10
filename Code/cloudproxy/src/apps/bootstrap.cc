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

#include <glog/logging.h>
#include <gflags/gflags.h>
#include "legacy_tao/legacy_tao.h"
#include "logging.h"

DEFINE_string(secret_path, "bootstrap_sealed_secret",
              "The path to the TPM-sealed key for this binary");
DEFINE_string(directory, "/home/jlm/jlmcrypt",
              "The directory to use for Tao initialization");
DEFINE_string(key_path, "bootstrap_files/bootstrap_key",
              "An encrypted keyczar directory for an encryption key");
DEFINE_string(pk_key_path, "bootstrap_files/bootstrap_pk_key",
              "An encrypted keyczar directory for a signing key");
DEFINE_bool(start_measured, false, "A flag that indicates measured boot");
DEFINE_string(whitelist, "signed_whitelist", "A signed whitelist file");
DEFINE_string(policy_pk_path, "./policy_public_key",
	      "The path to the public policy key");

int main(int argc, char **argv) {

  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InstallFailureSignalHandler();

  initLog(NULL);

  bool start_measured = false;

  // call this program like this:
  // ./bootstrap --start_measured -- <real flags for the instance>
  if (FLAGS_start_measured) {
    start_measured = true;
    FLAGS_log_dir = "b_orig";
  } else {
    FLAGS_log_dir = "b_meas";
  }

  FLAGS_alsologtostderr = true;
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
  scoped_ptr<tao::Tao> tao(new legacy_tao::LegacyTao(
      FLAGS_secret_path, FLAGS_directory, FLAGS_key_path, FLAGS_pk_key_path,
      FLAGS_whitelist, FLAGS_policy_pk_path));

  CHECK(tao->Init()) << "Could not initialize the Legacy Tao";
  LOG(INFO) << "Finished initializing the Legacy Tao";

  // now start the server and start listening for requests from it
  size_t slen = strlen("server");
  scoped_array<char> sname(new char[slen + 1]);
  strncpy(sname.get(), "server", slen + 1);
  char *server_name = sname.get();
  char *new_argv[] = { server_name };
  CHECK(tao->StartHostedProgram("server", 1, new_argv))
    << "Could not start the server under LegacyTao";
  return 0;
}
