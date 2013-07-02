#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <unistd.h>

#include <cstdio>
#include <memory>
#include <string>

using std::unique_ptr;
using std::string;

//#define READ_SIZE 1048576
#define READ_SIZE 16300

// rather than thinking about it, for now just double the size
#define ENC_SIZE 2*READ_SIZE
#define KEY_LEN 16
#define IV_LEN 16
#define HMAC_KEY_LEN 64
#define HMAC_OUT_LEN 32
#define UNUSEDVAR(x) \
  if (x) \
    ;

extern int errno;

// a program to set up a network connection and do one of four things
// 1. use no encryption on the channel and write the bits to standard output
// 2. like 1, but use TLSv1.2 on the channel with AES-128-CBC and HMAC-SHA256
// 3. like 2, but encrypt the bits with AES-CBC-128 with a random key and IV
// 4. like 3, but add HMAC-SHA256 integrity to the bits.
//
// To switch between these modes, we will take in exactly one argument and
// compare it to the following options
// 1. "none"
// 2. "tls"
// 3. "enc"
// 4. "full"
int main(int argc, char** argv) {

  // read the arguments to decide on the mode to use
  if (4 != argc) {
    fprintf(stderr, "Usage: %s <ipaddress> <port> <none | tls | enc | full>\n", argv[0]);
    exit(1);
  }

  string ipaddress(argv[1]);
  string port(argv[2]);

  string mode(argv[3]);
  bool use_tls = false;
  bool use_enc = false;
  bool use_hmac = false;
  if (mode.compare("none") == 0) {
    // do nothing, since this is the default setting
  } else if (mode.compare("tls") == 0) {
    use_tls = true;
  } else if (mode.compare("enc") == 0) {
    use_tls = true;
    use_enc = true;
  } else if (mode.compare("full") == 0) {
    use_tls = true;
    use_enc = true;
    use_hmac = true;
  } else {
    fprintf(stderr, "Usage: %s <none | tls | enc | full>\n", argv[0]);
    exit(1);
  }

  // make all the necessary calls to set up OpenSSL
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();

  SSL_library_init();

  BIO* bio = NULL;
  BIO* abio = NULL;
  BIO* out = NULL;

  // TODO: get these lengths from the cipher/hmac contexts themselves
  int key_len = KEY_LEN;
  int iv_len = IV_LEN;
  int hmac_key_len = HMAC_KEY_LEN;
  int hmac_out_len = HMAC_OUT_LEN;

  // an encryption cipher to use for this data
  EVP_CIPHER_CTX evp;
  unique_ptr<unsigned char[]> enc_key(new unsigned char[key_len]);
  unique_ptr<unsigned char[]> iv(new unsigned char[iv_len]);

  // an HMAC algorithm to use for this data
  HMAC_CTX hmac;
  unique_ptr<unsigned char[]> hmac_key(new unsigned char[hmac_key_len]);

  int ret = 0;
  try {
    FILE* rand_file = fopen("/dev/urandom", "rb");
    if (!rand_file)
      throw "Can't open /dev/urandom to generate a key";

    size_t bytes_read = 0;

    if (use_enc) {
      // set up AES-CBC-128 as the cipher, with a fresh key for now
      EVP_CIPHER_CTX_init(&evp);

      bytes_read = fread(enc_key.get(), 1, key_len, rand_file);
      // this cast is safe, since key_len > 0 holds
      if (bytes_read != static_cast<size_t>(key_len))
        throw "Could not get a new random key from /dev/urandom";

      bytes_read = fread(iv.get(), 1, iv_len, rand_file);
      // this cast is safe, since iv_len > 0 holds
      if (bytes_read != static_cast<size_t>(iv_len)) 
        throw "Could not get an initialization vector from /dev/urandom";

      // set up the cipher with AES-128 CBC
      EVP_EncryptInit_ex(&evp, EVP_aes_128_cbc(), NULL, enc_key.get(), iv.get());
    }

    if (use_hmac) {
      // set up HMAC-SHA256 as an integrity check on the data
      bytes_read = fread(hmac_key.get(), 1, hmac_key_len, rand_file);
      // this cast is safe, since hmac_key_len > 0 holds
      if (bytes_read != static_cast<size_t>(hmac_key_len))
        throw "Could not get a new random hmac key from /dev/urandom";

      HMAC_Init(&hmac, hmac_key.get(), hmac_key_len, EVP_sha256());
    }

    if (use_enc) {
      // write the IV before we start writing the encrypted data
      size_t bytes_written = fwrite(iv.get(), 1, iv_len, stdout);
      // iv_len > 0 holds, so this cast is safe
      if (bytes_written != static_cast<size_t>(iv_len))
        throw "Could not write the IV to standard output";

      if (use_hmac) {
        // add the IV to the HMAC computation
        if (!HMAC_Update(&hmac, iv.get(), iv_len))
          throw "Could not add the IV bytes to the HMAC computation";
      }
    }

    // set our SSL connection to use TLSv1.2
    if (use_tls) {
      SSL_CTX* ctx = NULL;
      ctx = SSL_CTX_new(TLSv1_2_server_method());
      if (NULL == ctx)
        throw "Can't create an ssl context";

      if (!SSL_CTX_set_cipher_list(ctx, "AES128-SHA256"))
        throw "Can't restrict the cipher list to AES128-SHA256";

      if (!SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION))
        throw "Can't turn off compression on this connection";

      SSL* ssl = NULL;

      // load trust database if we can
      if (!SSL_CTX_load_verify_locations(ctx, "certs/client.pem", NULL))
        throw "Can't load the trust database";

      // set the server certificate to use
      if (!SSL_CTX_use_certificate_file(ctx, "certs/server.pem", SSL_FILETYPE_PEM))
        throw "Can't use the server certificate";

      // set the server private key to use
      if (!SSL_CTX_use_PrivateKey_file(ctx, "certs/server.key", SSL_FILETYPE_PEM))
        throw "Can't load the server private key";

      bio = BIO_new_ssl(ctx, 0);
      if (NULL == bio)
        throw "Can't set up new connection";

      BIO_get_ssl(bio, &ssl);
      if (NULL == ssl)
        throw "Can't get the SSL object";

      SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    }

    // either way, set up a listener on the port
    string host_and_port = ipaddress + string(":") + port;
    abio = BIO_new_accept(const_cast<char*>(host_and_port.c_str()));

    if (use_tls) {
      // then hook up abio to the SSL bio we set up above
      BIO_set_accept_bios(abio, bio);
    }

    // set up the abio for accept
    if (BIO_do_accept(abio) <= 0)
      throw "Could not set up an accept operation on the port";

    // wait here for a connection from a client
    if (BIO_do_accept(abio) <= 0)
      throw "Failed to accept a connection";

    // when we get here, we got a connection request from a client
    out = BIO_pop(abio);
    if (NULL == out)
      throw "Failed to get an out BIO after accepting a connection";

    if (use_tls) {
      if (BIO_do_handshake(out) <= 0)
        throw "Failed to perform the handshake with the client";
    }

    // listen for data from the client and write it to standard output
    int len = READ_SIZE;
    unique_ptr<unsigned char[]> buf(new unsigned char[len]);
    int enc_buf_len = ENC_SIZE;
    int out_len = 0;
    unique_ptr<unsigned char[]> outbuf(new unsigned char[enc_buf_len]);
    int x = 0;
    while((x = BIO_read(out, buf.get(), len)) != 0) {
      if (x < 0) {
        if (!BIO_should_retry(bio)) break;
      } else {
        unsigned char* write_buf = buf.get();
        int write_buf_len = x;
        if (use_enc) {
          // encrypt the bytes
          out_len = enc_buf_len;
          if (!EVP_EncryptUpdate(&evp, outbuf.get(), &out_len, buf.get(), x))
            throw "Failed to encrypt the incoming data";

          if (use_hmac) {
            // add these bytes to the HMAC computation
            if (!HMAC_Update(&hmac, outbuf.get(), out_len))
              throw "Could not add the encrypted bytes to the HMAC computation";
          }

          write_buf = outbuf.get();
          write_buf_len = out_len;
        }

        // write the encrypted bytes to standard output and listen again
        // until the connection terminates
        size_t bytes_written = fwrite(write_buf, 1, write_buf_len, stdout);
        // note that this cast to size_t is safe, since x > 0
        if (bytes_written != static_cast<size_t>(write_buf_len))
          throw "bytes not successfully written to stdout";
      }
    }

    if (x == 0) {
      if (use_enc) {
        // write any final bytes for the encrypted data
        out_len = enc_buf_len;
        if (!EVP_EncryptFinal_ex(&evp, outbuf.get(), &out_len))
          throw "Failed to finalize the encryption";

        if (use_hmac && (out_len > 0)) {
          // add the final bytes to the HMAC computation
          if (!HMAC_Update(&hmac, outbuf.get(), out_len))
            throw "Could not add the final encrypted bytes to the HMAC computation";
        }

        size_t bytes_written = fwrite(outbuf.get(), 1, out_len, stdout);
        if (bytes_written != static_cast<size_t>(out_len))
          throw "final bytes not successfully written to stdout";

        if (use_hmac) {
          // finalize the HMAC computation and write it to the output
          unique_ptr<unsigned char[]> hmac_md(new unsigned char[hmac_out_len]);
          // this cast is safe, since hmac_out_len is small and hmac_out_len > 0
          unsigned int hmac_out_final_len = static_cast<unsigned int>(hmac_out_len);
          if (!HMAC_Final(&hmac, hmac_md.get(), &hmac_out_final_len))
            throw "Could not finalize the HMAC computation";

          bytes_written = fwrite(hmac_md.get(), 1, hmac_out_final_len, stdout);
          if (bytes_written != hmac_out_final_len)
            throw "Could not write the HMAC value to stdout";
        }
      }

      // do nothing if we're not encrypting the data, since we have already
      // written all the data to stdout
    } else if (x < 0) {
      throw "Connection failed during data transmission";
    }

    if (use_enc) {
      // clean up the cipher and the hmac
      EVP_CIPHER_CTX_cleanup(&evp);
      if (use_hmac)
        HMAC_CTX_cleanup(&hmac);
    }
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

  if (NULL != abio) {
    int res = BIO_reset(abio);
    UNUSEDVAR(res);

    BIO_free_all(abio);
  }

  if (NULL != out) {
    int res = BIO_reset(out);
    UNUSEDVAR(res);

    BIO_free_all(out);
  }

  return ret;
}

