#ifndef LEGACY_TAO_LEGACY_TAO_H_
#define LEGACY_TAO_LEGACY_TAO_H_

#include <keyczar/keyczar.h>
#include <keyczar/crypto_factory.h>

// jlm's taoHostServices and taoEnvironment
// along with startMeAsMeasuredProgram for clients of LegacyTao
#include <tao.h>

// tao::Tao
#include <tao/tao.h>

#include <string>
#include <map>

using std::string;
using std::map;

namespace legacy_tao {

class LegacyTao : public tao::Tao {
  public:
    LegacyTao(const string &secret_path, const string &directory,
	      const string &key_path, const string &pk_path,
	      const string &whitelist_path, const string &policy_pk_path);
    virtual ~LegacyTao() { }
    virtual bool Init();
    virtual bool Destroy();
    virtual bool StartHostedProgram(const string &path, int argc,
                                    char **argv);
    virtual bool GetRandomBytes(size_t size, string *bytes);
    virtual bool Seal(const string &data, string *sealed);
    virtual bool Unseal(const string &sealed, string *data);
    virtual bool Quote(const string &data, string *signature);
    virtual bool VerifyQuote(const string &data, const string &signature);
    virtual bool Attest(string *attestation);
    virtual bool VerifyAttestation(const string &attestation);

  private:
    // the path to the secret sealed by the legacy Tao
    string secret_path_;

    // the directory for legacy Tao initialization
    string directory_;

    // the path to the sealed keyczar key
    string key_path_;

    // the path to the sealed public/private keyczar key
    string pk_path_;

    // the path to the whitelist for programs to start
    string whitelist_path_;

    // the path to the public key
    string policy_pk_path_;

    // the legacy tao host and environment
    scoped_ptr<taoHostServices> tao_host_;
    scoped_ptr<taoEnvironment> tao_env_;

    // keys unlocked by the secret
    scoped_ptr<keyczar::Keyczar> crypter_;

    // public/private keys unlocked by crypter_
    scoped_ptr<keyczar::Keyczar> signer_;

    // the public policy key
    scoped_ptr<keyczar::Keyczar> policy_verifier_;

    // the verified whitelist of applications that can be started
    map<string, string> whitelist_;

    // A file descriptor used to communicate with the child process
    int child_fd_;

    static const int AesBlockSize = 16;
    static const int Sha256Size = 32;
    static const int SecretSize = 64;
    // until the Tao provides a way to get this info
    static const int SealedSize = 160;  

    // initializes the legacy tao by setting up tao_host_ and tao_env_
    bool initTao();

    // either unseal or create and seal a secret using the legacy tao
    bool getSecret(keyczar::base::ScopedSafeString *secret);

    // create a new keyset with a primary AES key that we will use as the
    // basis of the bootstrap Tao
    bool createKey(const string &secret);
    
    // create a new keyset with an ECDSA public/private key pair to use for
    // signing
    bool createPublicKey(keyczar::Encrypter *crypter);
};
} // namespace legacy_tao

#endif // LEGACY_TAO_LEGACY_TAO_H_
