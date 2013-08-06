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

#include "tao/hosted_programs.pb.h"

using std::string;
using std::stringstream;
using std::ifstream;
using std::ofstream;

DEFINE_string(whitelist_file, "whitelist",
    "The name of the whitelist protobuf file to sign");
DEFINE_string(whitelist_sig_file, "signed_whitelist",
    "The name of the signature file");
DEFINE_string(key_loc, "./policy_key", "The location of the private key");
DEFINE_string(pass, "cppolicy", "The password to use for this private key");

int main(int argc, char** argv) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  google::ParseCommandLineFlags(&argc, &argv, true);

  // load the protobuf file
  ifstream whitelist(FLAGS_whitelist_file.c_str());
  stringstream whitelist_buf;
  whitelist_buf << whitelist.rdbuf();

  // decrypt the private policy key so we can construct a signer
  keyczar::base::ScopedSafeString password(new string(FLAGS_pass));
  scoped_ptr<keyczar::rw::KeysetReader> reader(
      new keyczar::rw::KeysetPBEJSONFileReader(FLAGS_key_loc.c_str(),
                                               *password));

  // sign this serialized data with the keyset in FLAGS_key_loc
  scoped_ptr<keyczar::Keyczar> signer(keyczar::Signer::Read(*reader));
  CHECK(signer.get()) << "Could not initialize the signer from "
                      << FLAGS_key_loc;
  signer->set_encoding(keyczar::Keyczar::NO_ENCODING);

  // keyczar::Keyczar *signer = keyczar::Signer::Read("./tempk");
  // print out the length of the string representation of the whitelist file
  size_t len = whitelist_buf.str().size();
  CHECK(len > 0) << "Could not read any bytes from the whitelist file";
  string sig;
  CHECK(signer->Sign(whitelist_buf.str(), &sig))
    << "Could not sign whitelist file";

  tao::SignedWhitelist sw;
  sw.set_serialized_whitelist(whitelist_buf.str());
  sw.set_signature(sig);

  string serialized;
  CHECK(sw.SerializeToString(&serialized))
    << "Could not serialize the signed ACLs";

  ofstream sig_file(FLAGS_whitelist_sig_file.c_str());
  sig_file.write(serialized.data(), serialized.length());
  return 0;
}
