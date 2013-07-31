#ifndef TAO_BOOTSTRAP_H_
#define TAO_BOOTSTRAP_H_

// cloudproxy::Tao
#include <tao/tao.h>

// jlm's taoHostServices and taoEnvironment
// along with startMeAsMeasuredProgram for clients of Bootstrap
#include <tao.h>
#include <keyczar/keyczar.h>

namespace cloudproxy {

class Bootstrap : public Tao {
  public:
    Bootstrap(const string &secret_path, const string &directory,
	      const string &key_path) { }
    virtual ~Bootstrap() { }
    virtual bool Init();
    virtual bool Destroy();
    virtual bool StartHostedProgram(const string &path, int argc,
                                    char **argv);
    virtual bool GetRandomBytes(size_t size, string *bytes);
    virtual bool Seal(const string &data, string *sealed);
    virtual bool Unseal(const string &sealed, string *data);
    virtual bool Attest(const string &data, string *attested);
    virtual bool Verify(const string &attested);

  private:
    // the path to the secret sealed by the legacy Tao
    string secret_path_;

    // the directory for legacy Tao initialization
    string directory_;

    // the path to the sealed keyczar key
    string key_path_;

    // the legacy tao host and environment
    scoped_ptr<taoHostServices> tao_host_;
    scoped_ptr<taoEnvironment> tao_env_;

    // keys unlocked by the secret
    scoped_ptr<keyczar::Keyset> keyset_;

    // a reference to the current primary key from the keyset
    const keyczar::Key *key_;

    // A file descriptor used to communicate with the child process
    int child_fd_;

    const int AesBlockSize = 16;
    const int Sha256Size = 32;
    const int SecretSize = 64;
    const int SealedSize = 160;  // until the Tao provides a way to get this info

    // initializes the legacy tao by setting up tao_host_ and tao_env_
    bool initTao();

    // either unseal or create and seal a secret using the legacy tao
    bool getSecret(keyczar::base::ScopedSafeString *secret);

    // create a new keyset with a primary AES key that we will use as the
    // basis of the bootstrap Tao
    bool createKey(const string &secret);
};
} // namespace bootstrap

#endif // TAO_BOOTSTRAP_H_
