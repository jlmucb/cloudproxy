#include <memory>
#include <string>
#include <fstream>
#include <streambuf>
#include <sstream>

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <keyczar/keyczar.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/base/stl_util-inl.h>
#include <keyczar/rw/keyset_file_reader.h>
#include <google/protobuf/text_format.h>

#include "cloudproxy.pb.h"

using std::string;
using std::stringstream;
using std::unique_ptr;
using std::ifstream;
using std::ofstream;

DEFINE_string(signed_pub_key_file, "keys/tmroeder_pub_signed",
              "The name of the signature file");
DEFINE_string(key_loc, "./policy_public_key", "The location of the public key");

int main(int argc, char** argv) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  google::ParseCommandLineFlags(&argc, &argv, true);

  // load the signature
  ifstream sig(FLAGS_signed_pub_key_file.c_str());
  cloudproxy::SignedSpeaksFor ssf;
  ssf.ParseFromIstream(&sig);

  // get the public key for verification
  keyczar::Keyczar* verifier = keyczar::Verifier::Read(FLAGS_key_loc.c_str());
  CHECK(verifier) << "Could not get the public key for verification";

  verifier->set_encoding(keyczar::Keyczar::NO_ENCODING);

  CHECK(verifier->Verify(ssf.serialized_speaks_for(), ssf.signature()))
      << "Verify failed";

  LOG(INFO) << FLAGS_signed_pub_key_file << " contained a valid signature "
            << " under public key in " << FLAGS_key_loc;

  string text;
  cloudproxy::SpeaksFor sf;
  sf.ParseFromString(ssf.serialized_speaks_for());
  google::protobuf::TextFormat::PrintToString(sf, &text);
  LOG(INFO) << "The SpeaksFor says: " << text;
  return 0;
}
