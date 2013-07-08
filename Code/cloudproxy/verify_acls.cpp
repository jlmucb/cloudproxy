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

using std::string;
using std::stringstream;
using std::unique_ptr;
using std::ifstream;
using std::ofstream;

DEFINE_string(acl_file, "acls", "The name of the acl protobuf file to verify");
DEFINE_string(acl_sig_file, "acls_sig", "The name of the signature file");
DEFINE_string(key_loc, "./policy_public_key", "The location of the public key");

int main(int argc, char** argv) {
    google::ParseCommandLineFlags(&argc, &argv, true);

    // load the protobuf file
    ifstream acls(FLAGS_acl_file.c_str());
    stringstream acl_buf;
    acl_buf << acls.rdbuf();

    // load the signature
    ifstream sig(FLAGS_acl_sig_file.c_str());
    stringstream sig_buf;
    sig_buf << sig.rdbuf();

    // get the public key for verification
    keyczar::Keyczar *verifier = keyczar::Verifier::Read(FLAGS_key_loc.c_str());   
    CHECK(verifier) << "Could not get the public key for verification";

    // print out the length of the string representation of the acl file
    size_t len = acl_buf.str().size();
    CHECK(len > 0) << "Could not read any bytes from the acls file";

    CHECK(verifier->Verify(acl_buf.str(), sig_buf.str())) << "Verify failed";

    LOG(INFO) << FLAGS_acl_sig_file << " contained a valid signature for " <<
         FLAGS_acl_file << " under public key in " << FLAGS_key_loc;
    return 0;
}
