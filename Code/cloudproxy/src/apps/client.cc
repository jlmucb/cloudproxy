#include <gflags/gflags.h>
#include <glog/logging.h>
#include <openssl/ssl.h>
#include <keyczar/base/base64w.h>
#include "cloudproxy/cloud_client.h"
#include "cloudproxy/cloudproxy.pb.h"
#include "tao/pipe_tao_channel.h"

#include <string>

using std::string;

using cloudproxy::CloudClient;

using keyczar::base::Base64WEncode;

using tao::PipeTaoChannel;
using tao::TaoChannel;

DEFINE_string(client_cert, "./openssl_keys/client/client.crt",
              "The PEM certificate for the client to use for TLS");
DEFINE_string(client_key, "./openssl_keys/client/client.key",
              "The private key file for the client for TLS");

// this will be removed when get this password released by the TPM
DEFINE_string(client_password, "cpclient",
              "The private key file for the client for TLS");
DEFINE_string(policy_key, "./policy_public_key", "The keyczar public"
                                                 " policy key");
DEFINE_string(pem_policy_key, "./openssl_keys/policy/policy.crt",
              "The PEM public policy cert");
DEFINE_string(address, "localhost", "The address of the local server");
DEFINE_int32(port, 11235, "The server port to connect to");

int main(int argc, char** argv) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  google::ParseCommandLineFlags(&argc, &argv, false);

  FLAGS_alsologtostderr = true;
  google::InitGoogleLogging(argv[0]);

  // initialize OpenSSL
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();
  SSL_library_init();

  // try to establish a channel with the Tao
  int fds[2];
  CHECK(PipeTaoChannel::ExtractPipes(&argc, &argv, fds))
    << "Could not extract pipes from the end of the argument list";
  scoped_ptr<TaoChannel> channel(new PipeTaoChannel(fds));
  CHECK_NOTNULL(channel.get());

  LOG(INFO) << "Client successfully established communication with the Tao";
  int size = 6;
  string name_bytes;
  CHECK(channel->GetRandomBytes(size, &name_bytes))
    << "Could not get a random name from the Tao";

  LOG(INFO) << "About to create a client";
  CloudClient cc(FLAGS_client_cert, FLAGS_client_key,
		 FLAGS_client_password, FLAGS_policy_key,
		 FLAGS_pem_policy_key, FLAGS_address, FLAGS_port);

  LOG(INFO) << "Created a client";
  CHECK(cc.Connect()) << "Could not connect to the server at " << FLAGS_address
                      << ":" << FLAGS_port;
  LOG(INFO) << "Connected to the server";

  // create a random object name to write, getting randomness from the Tao

  // Base64 encode the bytes to get a printable name
  string name;
  CHECK(keyczar::base::Base64WEncode(name_bytes, &name)) << "Could not encode"
                                                            " name";

  // string name("test");
  CHECK(cc.AddUser("tmroeder", "./keys/tmroeder", "tmroeder"))
      << "Could not"
         " add the user credential from its keyczar path";
  LOG(INFO) << "Added credentials for the user tmroeder";
  CHECK(cc.Authenticate("tmroeder", "./keys/tmroeder_pub_signed"))
      << "Could"
         " not authenticate tmroeder with the server";
  LOG(INFO) << "Authenticated to the server for tmroeder";
  CHECK(cc.Create("tmroeder", name)) << "Could not create the object"
                                     << "'" << name << "' on the server";
  LOG(INFO) << "Created the object " << name;
  CHECK(cc.Read("tmroeder", name, name)) << "Could not read the object";
  LOG(INFO) << "Read the object " << name;
  CHECK(cc.Destroy("tmroeder", name)) << "Could not destroy the object";
  LOG(INFO) << "Destroyed the object " << name;

  CHECK(cc.Close(false)) << "Could not close the channel";

  LOG(INFO) << "Test succeeded";

  return 0;
}
