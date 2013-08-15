//  File: main.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An app to test protocol buffers and Keyczar
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

#include <memory>
#include <string>

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <keyczar/keyczar.h>
#include <keyczar/base/base64w.h>
#include <keyczar/base/scoped_ptr.h>

#include "cloudproxy/cloudproxy.pb.h"

using std::string;

DEFINE_string(subject, "", "The subject of the action");
DEFINE_string(operation, "ALL", "The operation to send");
DEFINE_string(object, "", "The object on which to operate");
DEFINE_string(key_loc, "/tmp/aes", "The location of the key set to use");

int main(int argc, char** argv) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  google::ParseCommandLineFlags(&argc, &argv, true);

  cloudproxy::Action action;
  action.set_subject(FLAGS_subject);

  cloudproxy::Op op = cloudproxy::ALL;
  CHECK(cloudproxy::Op_Parse(FLAGS_operation, &op)) << "Could not parse the"
                                                       " supplied operation";

  action.set_verb(op);
  action.set_object(FLAGS_object);

  string serialized;
  CHECK(action.SerializeToString(&serialized)) << "Could not serialize an"
                                                  " Action to a string\n";

  // encrypt this serialized data with the keyset in FLAGS_key_loc
  scoped_ptr<keyczar::Keyczar> crypter(keyczar::Crypter::Read(FLAGS_key_loc));
  CHECK(crypter.get()) << "Could not initialize the crypter from "
                       << FLAGS_key_loc;

  string ciphertext;
  CHECK(crypter->Encrypt(serialized, &ciphertext)) << "Could not encrypt"
                                                      " the serialized Action";

  string serializedBase64;
  CHECK(keyczar::base::Base64WEncode(serialized, &serializedBase64))
      << " Could not encode the serialized Action under base64w";
  LOG(INFO) << "Plaintext: " << serializedBase64;
  LOG(INFO) << "Ciphertext: " << ciphertext;

  // now decrypt and deserialize and check that everything matches
  string decrypted;
  CHECK(crypter->Decrypt(ciphertext, &decrypted))
      << "Could not decrypt"
         " the encrypted, serialized Action";

  cloudproxy::Action action2;
  action2.ParseFromString(decrypted);

  CHECK_STREQ(action.subject().c_str(), action2.subject().c_str())
      << "The original and deserialized subjects did not match\n";

  return 0;
}
