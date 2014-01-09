#include <fstream>
#include <sstream>

#include <glog/logging.h>
#include <gtest/gtest.h>
#include <keyczar/keyczar.h>
#include <keyczar/rw/keyset_file_writer.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "cloudproxy/cloudproxy.pb.h"
#include "cloudproxy/util.h"
#include "tao/util.h"

using cloudproxy::ACL;
using cloudproxy::Action;
using cloudproxy::CreateECDSAKey;
using cloudproxy::CreateECDSAPrivateKey;
using cloudproxy::CreateUserECDSAKey;
using cloudproxy::ExtractACL;
using cloudproxy::PasswordCallback;
using cloudproxy::ScopedFile;
using cloudproxy::ScopedEvpPkey;
using cloudproxy::ScopedSSLCtx;
using cloudproxy::SerializeX509;
using cloudproxy::SetUpSSLCTX;
using cloudproxy::SignedACL;
using cloudproxy::WriteECDSAKey;
using keyczar::Keyczar;
using keyczar::rw::KeysetJSONFileWriter;
using std::ifstream;
using std::ofstream;
using std::stringstream;
using tao::CreateTempDir;
using tao::CreateTempPubKey;
using tao::ScopedTempDir;
using tao::SignData;

TEST(CloudProxyUtilTest, PasswordCallbackTest) {
  string password("password");
  scoped_array<char> buf(new char(password.size() + 1));
  EXPECT_EQ(PasswordCallback(buf.get(), password.size() + 1, 0,
                             (void *)password.c_str()),
            static_cast<int>(password.size()));
  EXPECT_STREQ(buf.get(), password.c_str());
}

TEST(CloudProxyUtilTest, SetUpSSLCTXTest) {
  ScopedTempDir temp_dir;
  scoped_ptr<Keyczar> policy_key;
  ASSERT_TRUE(CreateTempPubKey(&temp_dir, &policy_key))
      << "Could not create a policy key";

  // Export a public version of the keyset to policy_pub_key_path
  string policy_keypath = *temp_dir + string("/policy_pk");
  string policy_pub_key_path = *temp_dir + string("/pub_policy_key");
  ASSERT_EQ(mkdir(policy_pub_key_path.c_str(), 0700), 0);
  KeysetJSONFileWriter writer(policy_pub_key_path);
  ASSERT_TRUE(policy_key->keyset()->PublicKeyExport(writer));

  // Export the keyczar key to an encrypted PEM file.
  string policy_pub_key_pem = *temp_dir + string("/pub_policy.pem");
  string dummy_password("dummy_password");
  string policy_keypem = *temp_dir + string("/policy.key");
  ASSERT_TRUE(policy_key->keyset()->ExportPrivateKey(policy_keypem,
                                                      &dummy_password));

  // Keyczar is evil and runs EVP_cleanup(), which removes all the symbols.
  // So, they need to be added again.
  OpenSSL_add_all_algorithms();
  // Now import the OpenSSL key and write its public counterpart.
  const char *dp = "dummy_password";
  BIO *ec_file = BIO_new(BIO_s_file());
  BIO_read_filename(ec_file, policy_keypem.c_str());
  EC_KEY *pk = PEM_read_bio_ECPrivateKey(ec_file, NULL, NULL, (void *)dp);
  ASSERT_TRUE(pk != nullptr);
  BIO_free(ec_file);
  ScopedEvpPkey pk_evp(EVP_PKEY_new());
  ASSERT_TRUE(EVP_PKEY_assign_EC_KEY(pk_evp.get(), pk));

  // This call from tao/util.h creates a self-signed X.509 certificate for the
  // key. It also writes a version of the private key, which we will put in a
  // dummy location for the purposes of this test.
  string dummy_private = *temp_dir + string("/dummy_private.key");
  ASSERT_TRUE(WriteECDSAKey(pk_evp, dummy_private, policy_pub_key_pem,
                            dummy_password, "US", "Google", "Policy Key"));
  string client_tls_cert = *temp_dir + string("/cert");
  string client_tls_key = *temp_dir + string("/key");
  EXPECT_TRUE(CreateECDSAKey(client_tls_key, client_tls_cert, "dummy_password",
                             "US", "Google", "client"));

  ScopedSSLCtx ctx(SSL_CTX_new(TLSv1_2_client_method()));
  EXPECT_TRUE(SetUpSSLCTX(ctx.get(), policy_pub_key_path,
                          client_tls_cert, client_tls_key, "dummy_password"));
}

TEST(CloudProxyUtilTest, ExtractACLTest) {
  ScopedTempDir temp_dir;
  scoped_ptr<Keyczar> policy_public_key;
  EXPECT_TRUE(CreateTempPubKey(&temp_dir, &policy_public_key))
      << "Could not create a public key";

  // Set up a simple ACL to query.
  ACL acl;
  Action *a1 = acl.add_permissions();
  a1->set_subject("tmroeder");
  a1->set_verb(cloudproxy::ADMIN);

  Action *a2 = acl.add_permissions();
  a2->set_subject("jlm");
  a2->set_verb(cloudproxy::CREATE);
  a2->set_object("/files");

  SignedACL sacl;
  string *ser = sacl.mutable_serialized_acls();
  EXPECT_TRUE(acl.SerializeToString(ser)) << "Could not serialize ACL";

  string *sig = sacl.mutable_signature();
  EXPECT_TRUE(SignData(*ser, sig, policy_public_key.get()))
      << "Could not sign the serialized ACL with the policy key";

  string signed_acl_path = *temp_dir + string("/signed_acl");
  ofstream acl_file(signed_acl_path.c_str(), ofstream::out);
  ASSERT_TRUE(acl_file) << "Could not open " << signed_acl_path;

  EXPECT_TRUE(sacl.SerializeToOstream(&acl_file))
      << "Could not write the signed acl to a file";

  acl_file.close();

  string acl_out;
  EXPECT_TRUE(ExtractACL(signed_acl_path, policy_public_key.get(), &acl_out));
  ACL deserialized_acl;
  EXPECT_TRUE(deserialized_acl.ParseFromString(acl_out));
}

TEST(CloudProxyUtilTest, X509ECDSATest) {
  ScopedEvpPkey key;
  ScopedTempDir temp_dir;

  EXPECT_TRUE(CreateECDSAPrivateKey(&key));
  EXPECT_TRUE(CreateTempDir("x509_test", &temp_dir));

  string private_path = *temp_dir + string("/temp.key");
  string public_path = *temp_dir + string("/temp.pem");
  string secret("secret");

  EXPECT_TRUE(WriteECDSAKey(key, private_path, public_path, secret, "US",
                            "Google", "Test Key"));

  ScopedFile x509_file(fopen(public_path.c_str(), "r"));
  ASSERT_TRUE(x509_file.get() != nullptr);
  X509 *x = nullptr;
  PEM_read_X509(x509_file.get(), &x, nullptr, nullptr);
  ASSERT_TRUE(x != nullptr);

  string serialized_x509;
  EXPECT_TRUE(SerializeX509(x, &serialized_x509));
}

TEST(CloudProxyUtilTest, KeyczarECDSATest) {
  scoped_ptr<Keyczar> out_key;
  ScopedTempDir temp_dir;
  ASSERT_TRUE(CreateTempDir("keyczar_ecdsa_test", &temp_dir));
  string key_dir = *temp_dir + string("/key");
  ASSERT_EQ(mkdir(key_dir.c_str(), 0700), 0);

  EXPECT_TRUE(CreateUserECDSAKey(key_dir, "key", "password", &out_key));
}
