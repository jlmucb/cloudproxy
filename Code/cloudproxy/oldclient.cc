#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <unistd.h>
#include <errno.h>

#include <cstdio>
#include <memory>
#include <string>

using std::unique_ptr;
using std::string;

//#define READ_SIZE 1048576
#define READ_SIZE 16300
#define UNUSEDVAR(x) \
  if (x) \
    ;

extern int errno;

// a program to set up a network connection and do one of two things
// 1. use no encryption on the channel and read bits from stdin
// 2. like 1, but use TLSv1.2 on the channel with AES-128-CBC and HMAC-SHA256
//
// To switch between these modes, we will take in exactly one argument and
// compare it to the following options
// 1. "none"
// 2. "tls" or "enc" or "full"
int main(int argc, char** argv) {
  // read the arguments to decide on the mode to use
  if (4 != argc) {
    fprintf(stderr, "Usage: %s <server_ip> <server_port> <none | tls | enc | full>\n", argv[0]);
    exit(1);
  }

  string ipaddress(argv[1]);
  string port(argv[2]);
  string mode(argv[3]);
  bool use_tls = false;
  if (mode.compare("none") == 0) {
    // do nothing, since this is the default setting
  } else if ((mode.compare("tls") == 0) ||
             (mode.compare("enc") == 0) ||
             (mode.compare("full") == 0)) {
    use_tls = true;
  } else {
    fprintf(stderr, "Usage: %s <none | tls>\n", argv[0]);
    exit(1);
  }

  SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();

  SSL_library_init();

  BIO* bio = NULL;
  int ret = 0;
  try {
    string host_and_port = ipaddress + string(":") + port;
    if (use_tls) {
      SSL_CTX* ctx = SSL_CTX_new(TLSv1_2_client_method());
      if (NULL == ctx)
        throw "Can't create an ssl context";

      if (!SSL_CTX_set_cipher_list(ctx, "AES128-SHA256"))
        throw "Can't restrict the cipher list to AES128-SHA256";

      if (!SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION))
        throw "Can't turn off compression for this connection";

      SSL* ssl = NULL;

      // load trust database if we can
      if (!SSL_CTX_load_verify_locations(ctx, "certs/server.pem", NULL))
        throw "Can't load the trust database";

      // set the client certificate to use
      if (!SSL_CTX_use_certificate_file(ctx, "certs/client.pem", SSL_FILETYPE_PEM))
        throw "Can't use the client certificate";

      // set the client private key to use
      if (!SSL_CTX_use_PrivateKey_file(ctx, "certs/client.key", SSL_FILETYPE_PEM))
        throw "Can't load the client private key";

      bio = BIO_new_ssl_connect(ctx);
      if (NULL == bio)
        throw "Can't set up new connection";

      BIO_get_ssl(bio, &ssl);
      if (NULL == ssl)
        throw "Can't get the SSL object";

      SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
      BIO_set_conn_hostname(bio, const_cast<char*>(host_and_port.c_str()));
    } else {
      bio = BIO_new_connect(const_cast<char*>(host_and_port.c_str()));
    }

    if (BIO_do_connect(bio) <= 0)
      throw "Connection failed";

    // read from stdin and write to the bio until we don't have any more data on
    // stdin
    unique_ptr<unsigned char[]> input(new unsigned char[READ_SIZE]);
    size_t bytesRead = 0;
    while((bytesRead = fread(input.get(), 1, READ_SIZE, stdin)) != 0) {
      // send the data on the bio
      int x = 0;
      while((x = BIO_write(bio, input.get(), bytesRead)) < 0) {
        if (!BIO_should_retry(bio)) break;
      }

      if (x <= 0)
        throw "Unrecoverable error on the TLS connection";
    }

    if (!feof(stdin))
      throw "Failed to read all input";

  } catch (const char* err) {
    fprintf(stderr, "Connection failed with error '%s'\n", err);
    char* errString = ERR_error_string(ERR_get_error(), NULL);
    if (NULL != errString) {
      fprintf(stderr, "%s\n", errString);
    }
    ret = 1;
  }

  if (NULL != bio) {
    int res = BIO_reset(bio);
    UNUSEDVAR(res);

    BIO_free_all(bio);
  }

  return ret;
}
