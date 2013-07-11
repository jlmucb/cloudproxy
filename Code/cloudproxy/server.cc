#include <gflags/gflags.h>
#include <glog/logging.h>
#include "cloud_server.h"

#include <string>

using std::string;

DEFINE_string(server_cert, "./openssl_keys/server/server.pem",
		"The PEM certificate for the server to use for TLS");
DEFINE_string(server_key, "./openssl_keys/server/server.key",
		"The private key file for the server for TLS");
DEFINE_string(policy_key, "./public_policy_key", "The keyczar public"
		" policy key");
DEFINE_string(pem_policy_key, "./openssl_keys/policy/policy.pem",
		"The PEM public policy cert");
DEFINE_string(acls, "./acls_sig", "A file containing a SignedACL signed by"
		" the public policy key (e.g., using sign_acls)");
DEFINE_string(server_enc_key, "./server_key", "A keyczar crypter"
        " directory");
DEFINE_string(address, "localhost", "The address to listen on");
DEFINE_int32(port, 11235, "The port to listen on");

int main(int argc, char **argv) {
    // make sure protocol buffers is using the right version
    GOOGLE_PROTOBUF_VERIFY_VERSION;

    google::ParseCommandLineFlags(&argc, &argv, true);
    
    // initialize OpenSSL
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    SSL_library_init();

    cloudproxy::CloudServer cs(FLAGS_server_cert,
                               FLAGS_server_key,
                               FLAGS_policy_key,
                               FLAGS_pem_policy_key,
                               FLAGS_acls,
                               FLAGS_server_enc_key,
                               FLAGS_address,
                               FLAGS_port);

    CHECK(cs.Listen()) << "Could not listen for client connections";
    return 0;
}
