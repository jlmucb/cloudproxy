#include <gflags/gflags.h>
#include <glog/logging.h>

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include "cloudproxy/cloud_server.h"
#include <tao/pipe_tao_channel.h>

#include <mutex>
#include <string>
#include <vector>

using std::mutex;
using std::string;
using std::vector;

using cloudproxy::CloudServer;

using tao::PipeTaoChannel;
using tao::TaoChannel;

DEFINE_string(server_cert, "./openssl_keys/server/server.crt",
              "The PEM certificate for the server to use for TLS");
DEFINE_string(server_key, "./openssl_keys/server/server.key",
              "The private key file for the server for TLS");
DEFINE_string(server_password, "cpserver", "The password for the server key");
DEFINE_string(policy_key, "./policy_public_key", "The keyczar public"
                                                 " policy key");
DEFINE_string(pem_policy_key, "./openssl_keys/policy/policy.crt",
              "The PEM public policy cert");
DEFINE_string(acls, "./acls_sig",
              "A file containing a SignedACL signed by"
              " the public policy key (e.g., using sign_acls)");
DEFINE_string(address, "localhost", "The address to listen on");
DEFINE_int32(port, 11235, "The port to listen on");

vector<shared_ptr<mutex> > locks;

void locking_function(int mode, int n, const char *file, int line) {
  if (mode & CRYPTO_LOCK) {
    locks[n]->lock();
  } else {
    locks[n]->unlock();
  }
}

int main(int argc, char **argv) {
  // make sure protocol buffers is using the right version
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  google::ParseCommandLineFlags(&argc, &argv, true);

  FLAGS_alsologtostderr = true;
  google::InitGoogleLogging(argv[0]);

  // try to establish a channel with the Tao
  int fds[2];
  CHECK(PipeTaoChannel::ExtractPipes(&argc, &argv, fds))
    << "Could not extract pipes from the end of the argument list";
  scoped_ptr<TaoChannel> channel(new PipeTaoChannel(fds));
  CHECK_NOTNULL(channel.get());

  LOG(INFO) << "Successfully established communication with the Tao";
  int size = 16;
  string rand_bytes;
  CHECK(channel->GetRandomBytes(size, &rand_bytes))
    << "Could not get random bytes from the Tao";

  LOG(INFO) << "Got random bytes from the Tao";

  // initialize OpenSSL
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();
  SSL_library_init();

  // set up locking in OpenSSL
  int lock_count = CRYPTO_num_locks();
  locks.resize(lock_count);
  for (int i = 0; i < lock_count; i++) {
    locks[i].reset(new mutex());
  }
  CRYPTO_set_locking_callback(locking_function);

  CloudServer cs(FLAGS_server_cert, FLAGS_server_key,
		 FLAGS_server_password, FLAGS_policy_key,
		 FLAGS_pem_policy_key, FLAGS_acls, FLAGS_address,
		 FLAGS_port);

  CHECK(cs.Listen()) << "Could not listen for client connections";
  return 0;
}
