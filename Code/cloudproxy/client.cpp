#include <gflags/gflags.h>
#include <glog/logging.h>
#include "cloud_client.h"
#include "cloudproxy.pb.h"

DEFINE_int32(port, 0, "The server port to connect to");
DEFINE_string(address, "localhost", "The address of the local server");

int main(int argc, char** argv) {
    GOOGLE_PROTOBUF_VERIFY_VERSION;

    google::ParseCommandLineFlags(&argc, &argv, false);

    cloudproxy::CloudClient cc("./keys",
			       "./openssl_keys/client",
			       "./public_policy_key",
                               FLAGS_address, 
			       FLAGS_port);

    CHECK(cc.Connect()) << "Could not connect to the server at "
                      << FLAGS_address << ":" << FLAGS_port;
                    

    CHECK(cc.Authenticate("tmroeder")) << "Could not get keys from ./keys/"
        "tmroeder";
    CHECK(cc.Create("tmroeder", "test")) << "Could not create the object"
        " 'test' on the server";
    CHECK(cc.Read("tmroeder", "test")) << "Could not read the object";
    CHECK(cc.Destroy("tmroeder", "test")) << "Could not destroy the object";

    return 0;
}
