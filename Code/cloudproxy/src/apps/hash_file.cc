#include <keyczar/keyczar.h>
#include <keyczar/base/base64w.h>
#include <keyczar/crypto_factory.h>
#include <gflags/gflags.h>

#include <fstream>
#include <streambuf>
#include <sstream>
#include <string>

using std::ifstream;
using std::string;
using std::stringstream;

DEFINE_string(file, "", "The file to sign");

int main(int argc, char **argv) {
    google::ParseCommandLineFlags(&argc, &argv, true);

    CHECK(!FLAGS_file.empty()) << "Must specify a file";

    // get a fresh key that can be used for hashing
    keyczar::MessageDigestImpl *sha256 = keyczar::CryptoFactory::SHA256();

    ifstream file(FLAGS_file.c_str(), ifstream::in);
    stringstream file_buf;
    file_buf << file.rdbuf();

    string digest;
    CHECK(sha256->Digest(file_buf.str(), &digest))
        << "Could not compute a SHA-256 hash over the file " << FLAGS_file;

  string serializedBase64;
  CHECK(keyczar::base::Base64WEncode(digest, &serializedBase64))
      << " Could not encode the digest under base64w";
    LOG(INFO) << "Digest of file " << FLAGS_file << " was: " << serializedBase64;
    
    return 0;
}
