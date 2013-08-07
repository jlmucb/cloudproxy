#ifndef TAO_TAO_H_
#define TAO_TAO_H_

#include <string>

using std::string;

namespace tao {

// The Tao interface
class Tao {
  public:
    virtual ~Tao() { }
    virtual bool Init() = 0;
    virtual bool Destroy() = 0;
    virtual bool StartHostedProgram(const string &path, int argc,
                                    char **argv) = 0;
    virtual bool GetRandomBytes(size_t size, string *bytes) = 0;
    virtual bool Seal(const string &data, string *sealed) = 0;
    virtual bool Unseal(const string &sealed, string *data) = 0;
    virtual bool Quote(const string &data, string *signature) = 0;
    virtual bool VerifyQuote(const string &data, const string &signature) = 0;
    virtual bool Attest(string *attestation) = 0;
    virtual bool Verify(const string &attestation) = 0;
};
}

#endif // TAO_TAO_H_
