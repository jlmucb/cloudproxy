#include <gflags/gflags.h>
#include <glog/logging.h>
#include "cloud_client.h"
#include "cloudproxy.pb.h"

#include <string>

using std::string;

DEFINE_string(client_cert, "./openssl_keys/client/client.pem",
		"The PEM certificate for the client to use for TLS");
DEFINE_string(client_key, "./openssl_keys/client/client.key",
		"The private key file for the client for TLS");
DEFINE_string(policy_key, "./public_policy_key", "The keyczar public"
		" policy key");
DEFINE_string(pem_policy_key, "./openssl_keys/policy/policy.pem",
		"The PEM public policy cert");
DEFINE_string(address, "localhost", "The address of the local server");
DEFINE_int32(port, 11235, "The server port to connect to");

int main(int argc, char** argv) {
    GOOGLE_PROTOBUF_VERIFY_VERSION;

    google::ParseCommandLineFlags(&argc, &argv, false);

    cloudproxy::CloudClient cc(FLAGS_client_cert,
                               FLAGS_client_key,
                               FLAGS_policy_key,
                               FLAGS_pem_policy_key,
                               FLAGS_address, 
                               FLAGS_port);

    CHECK(cc.Connect()) << "Could not connect to the server at "
                      << FLAGS_address << ":" << FLAGS_port;
                    

    CHECK(cc.AddUser("tmroeder", "./keys/tmroeder", "tmroeder")) << "Could not"
      " add the user credential from its keyczar path";
    CHECK(cc.Authenticate("tmroeder", "./keys/tmroeder_pub_signed")) << "Could"
      " not authenticate tmroeder with the server";
    CHECK(cc.Create("tmroeder", "test")) << "Could not create the object"
        " 'test' on the server";
    CHECK(cc.Read("tmroeder", "test")) << "Could not read the object";
    CHECK(cc.Destroy("tmroeder", "test")) << "Could not destroy the object";

    LOG(INFO) << "Test succeeded";

    return 0;
}
