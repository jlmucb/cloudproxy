//  File: linux_tao_test.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A test of the LinuxTao using the FakeTao
//
//  Copyright (c) 2013, Google Inc.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <glog/logging.h>
#include <gflags/gflags.h>
#include "tao/direct_tao_child_channel.h"
#include "tao/fake_program_factory.h"
#include "tao/fake_tao.h"
#include "tao/fake_tao_channel.h"
#include "tao/hosted_programs.pb.h"
#include "tao/hosted_program_factory.h"
#include "tao/linux_tao.h"
#include "tao/pipe_tao_channel.h"
#include "tao/process_factory.h"
#include "tao/util.h"
#include "tao/whitelist_auth.h"

#include <keyczar/base/base64w.h>
#include <keyczar/crypto_factory.h>
#include <keyczar/rw/keyset_file_writer.h>
#include <keyczar/rw/keyset_file_reader.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <fstream>
#include <memory>
#include <streambuf>
#include <sstream>
#include <string>

using std::ifstream;
using std::mutex;
using std::string;
using std::stringstream;
using std::vector;

using keyczar::Keyczar;
using keyczar::KeyPurpose;
using keyczar::KeyType;
using keyczar::Signer;
using keyczar::rw::KeysetJSONFileWriter;
using keyczar::rw::KeysetWriter;

using std::ifstream;
using std::ofstream;
using std::shared_ptr;
using std::string;
using std::stringstream;

using tao::CreateKey;
using tao::DirectTaoChildChannel;
using tao::FakeProgramFactory;
using tao::FakeTao;
using tao::FakeTaoChannel;
using tao::HostedProgram;
using tao::HostedProgramFactory;
using tao::LinuxTao;
using tao::PipeTaoChannel;
using tao::ProcessFactory;
using tao::SignedWhitelist;
using tao::Tao;
using tao::TaoChannel;
using tao::TaoChildChannel;
using tao::Whitelist;
using tao::WhitelistAuth;

DEFINE_string(program, "server", "The program to run");

vector<shared_ptr<mutex> > locks;

void locking_function(int mode, int n, const char *file, int line) {
  if (mode & CRYPTO_LOCK) {
    locks[n]->lock();
  } else {
    locks[n]->unlock();
  }
}

int main(int argc, char **argv) {

  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InstallFailureSignalHandler();

  FLAGS_alsologtostderr = true;
  google::InitGoogleLogging(argv[0]);
  // initialize OpenSSL
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  SSL_library_init();

  // set up locking in OpenSSL
  int lock_count = CRYPTO_num_locks();
  locks.resize(lock_count);
  for (int i = 0; i < lock_count; i++) {
    locks[i].reset(new mutex());
  }
  CRYPTO_set_locking_callback(locking_function);

  scoped_ptr<FakeTao> ft(new FakeTao());
  CHECK(ft->Init()) << "Could not init the FakeTao";

  string fake_linux_tao_hash("This is not a real hash");
  scoped_ptr<DirectTaoChildChannel> channel(
      new DirectTaoChildChannel(ft.release(), fake_linux_tao_hash));
  CHECK(channel->Init()) << "Could not init the channel";

  scoped_ptr<HostedProgramFactory> program_factory(new ProcessFactory());
  scoped_ptr<TaoChannel> pipe_channel(
      new PipeTaoChannel("/tmp/.server_test_socket"));

  // get a temporary directory to use for the files
  string dir_template("/tmp/server_test_XXXXXX");
  scoped_array<char> temp_name(new char[dir_template.size() + 1]);
  memcpy(temp_name.get(), dir_template.data(), dir_template.size() + 1);

  CHECK(mkdtemp(temp_name.get()));
  string dir = temp_name.get();

  string secret_path = dir + "/linux_tao_secret";
  string key_path = dir + "/linux_tao_secret_key";
  string pk_path = dir + "/linux_tao_pk";
  string whitelist_path = dir + "/whitelist";
  string policy_pk_path = dir + "/policy_pk";

  string server_binary_path = "./server";

  ifstream file(server_binary_path.c_str(), ifstream::in);
  stringstream file_buf;
  file_buf << file.rdbuf();

  string server_digest;
  keyczar::MessageDigestImpl *sha256 = keyczar::CryptoFactory::SHA256();
  CHECK(sha256->Digest(file_buf.str(), &server_digest))
      << "Could not compute a SHA-256 hash over the file './server'";

  string serializedBase64;
  CHECK(keyczar::base::Base64WEncode(server_digest, &serializedBase64))
      << " Could not encode the digest under base64w";

  LOG(INFO) << "Got server digest " << serializedBase64;
  // Create the policy key directory so it can be filled by keyczar.
  CHECK_EQ(mkdir(policy_pk_path.c_str(), 0700), 0);

  LOG(INFO) << "Created directories in " << dir;

  // create the policy key
  FilePath fp(policy_pk_path);
  scoped_ptr<KeysetWriter> policy_pk_writer(new KeysetJSONFileWriter(fp));
  scoped_ptr<Keyczar> policy_key;
  CHECK(CreateKey(policy_pk_writer.get(), KeyType::ECDSA_PRIV,
                  KeyPurpose::SIGN_AND_VERIFY, "policy_pk", &policy_key));
  policy_key->set_encoding(Keyczar::NO_ENCODING);

  // Create a whitelist with a dummy hosted program, since we don't
  // want the LinuxTao to start any hosted programs during this
  // test. Then write it to the temp filename above.
  Whitelist w;
  HostedProgram *hp = w.add_programs();
  hp->set_name(server_binary_path);
  hp->set_hash_alg("SHA256");
  hp->set_hash(serializedBase64);

  SignedWhitelist sw;
  string *serialized_whitelist = sw.mutable_serialized_whitelist();
  CHECK(w.SerializeToString(serialized_whitelist));

  string *signature = sw.mutable_signature();
  CHECK(policy_key->Sign(*serialized_whitelist, signature));

  ofstream whitelist_file(whitelist_path.c_str(), ofstream::out);
  CHECK(sw.SerializeToOstream(&whitelist_file));
  whitelist_file.close();

  scoped_ptr<WhitelistAuth> whitelist_auth(
      new WhitelistAuth(whitelist_path, policy_pk_path));
  CHECK(whitelist_auth->Init()) << "Could not initialize the whitelist";

  scoped_ptr<Tao> tao(
      new LinuxTao(secret_path, key_path, pk_path, policy_pk_path,
                   channel.release(), pipe_channel.release(),
                   program_factory.release(), whitelist_auth.release()));
  CHECK(tao->Init());

  list<string> args;
  CHECK(tao->StartHostedProgram(server_binary_path, args))
      << "Could not start the server under LinuxTao";
  // TODO(tmroeder): set this to wait for the listening threads. Or have it
  // listen for incoming StartHostedProgram messages
  while (true)
    ;
  return 0;
}
