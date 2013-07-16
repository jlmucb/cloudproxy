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
#include "util.h"

using std::string;
using std::stringstream;
using std::unique_ptr;
using std::ifstream;
using std::ofstream;

DEFINE_string(acl_sig_file, "acls_sig", "The name of the signature file");
DEFINE_string(key_loc, "./policy_public_key", "The location of the public key");

int main(int argc, char** argv) {
    GOOGLE_PROTOBUF_VERIFY_VERSION;

    google::ParseCommandLineFlags(&argc, &argv, true);

    // get the public key for verification
    unique_ptr<keyczar::Keyczar> verifier(keyczar::Verifier::Read(FLAGS_key_loc.c_str()));
    CHECK(verifier.get()) << "Could not get the public key for verification";
    verifier->set_encoding(keyczar::Keyczar::NO_ENCODING);

    string serialized_acl;
    CHECK(cloudproxy::ExtractACL(FLAGS_acl_sig_file, verifier.get(), &serialized_acl)) <<
      "Could not verify and load the ACL file";

    string text;
    cloudproxy::ACL acls;
    acls.ParseFromString(serialized_acl);
    google::protobuf::TextFormat::PrintToString(acls, &text);
    LOG(INFO) << "The ACLs are: " << text;
    return 0;
}
