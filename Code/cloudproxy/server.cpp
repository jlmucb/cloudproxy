#include <gflags/gflags.h>
#include <glog/logging.h>
#include "cloudserver.h"

DEFINE_int32(port, 0, "The port to listen on");

int main(int argc, char **argv) {
    GOOGLE_PROTOBUF_VERIFY_VERSION;

    google::ParseCommandLineFlags(&argc, &argv, true);
    
    cloudproxy::CloudServer cs("./openssl_keys/server",
			       "./public_policy_key",
			       "./openssl_keys/policy",
			       "./acls",
			       FLAGS_port);

    cs.Listen();
    return 0;
}
