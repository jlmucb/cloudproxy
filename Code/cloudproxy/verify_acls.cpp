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

DEFINE_string(acl_sig_file, "acls_sig", "The name of the signature file");
DEFINE_string(key_loc, "./policy_public_key", "The location of the public key");

int main(int argc, char** argv) {
    GOOGLE_PROTOBUF_VERIFY_VERSION;

    google::ParseCommandLineFlags(&argc, &argv, true);

    // load the signature
    ifstream sig(FLAGS_acl_sig_file.c_str());
    stringstream sig_buf;
    sig_buf << sig.rdbuf();

    cloudproxy::SignedACL sacl;
    sacl.ParseFromString(sig_buf.str());

    // get the public key for verification
    keyczar::Keyczar *verifier = keyczar::Verifier::Read(FLAGS_key_loc.c_str());   
    CHECK(verifier) << "Could not get the public key for verification";

    CHECK(verifier->Verify(sacl.serialized_acls(), sacl.signature())) << "Verify failed";

    LOG(INFO) << FLAGS_acl_sig_file << " contained a valid signature " <<
        " under public key in " << FLAGS_key_loc;

    string text;
    cloudproxy::ACL acls;
    acls.ParseFromString(sacl.serialized_acls());
    google::protobuf::TextFormat::PrintToString(acls, &text);
    LOG(INFO) << "The ACLs are: " << text;
    return 0;
}
