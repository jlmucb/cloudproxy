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

#include <cloudproxy.pb.h>

using std::string;
using std::stringstream;
using std::ifstream;
using std::ofstream;

DEFINE_string(acl_file, "acls", "The name of the acl protobuf file to sign");
DEFINE_string(acl_sig_file, "acls_sig", "The name of the signature file");
DEFINE_string(key_loc, "./policy_key", "The location of the private key");
DEFINE_string(pass, "cppolicy", "The password to use for this private key");

int main(int argc, char** argv) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  google::ParseCommandLineFlags(&argc, &argv, true);

  // load the protobuf file
  ifstream acls(FLAGS_acl_file.c_str());
  stringstream acl_buf;
  acl_buf << acls.rdbuf();

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
  // print out the length of the string representation of the acl file
  size_t len = acl_buf.str().size();
  CHECK(len > 0) << "Could not read any bytes from the acls file";
  string sig;
  CHECK(signer->Sign(acl_buf.str(), &sig)) << "Could not sign acl file";

  cloudproxy::SignedACL sacl;
  sacl.set_serialized_acls(acl_buf.str());
  sacl.set_signature(sig);

  string serialized;
  CHECK(sacl.SerializeToString(&serialized)) << "Could not serialize the"
                                                " signed ACLs";

  ofstream sig_file(FLAGS_acl_sig_file.c_str());
  sig_file.write(serialized.data(), serialized.length());
  return 0;
}
