#ifndef TAO_TAO_CHANNEL_H_
#define TAO_TAO_CHANNEL_H_

#include "tao/tao.h"
#include "tao/tao_channel_rpc.pb.h"

namespace tao {
  // an RPC class that communicates with a remote Tao server. It takes the input parameters, bundles them up, and sends them along a channel (details of the channel depend on the implementation)
  class TaoChannel : public Tao {
  public:
    virtual ~TaoChannel() { }

    // listen on the channel and handle incoming messages by passing them to the Tao
    bool Listen(Tao *t) const;

    // Tao interface methods
    virtual bool Init() { return true; }
    virtual bool Destroy() { return true; }
    virtual bool StartHostedProgram(const string &path, int argc,
                                    char **argv);
    virtual bool GetRandomBytes(size_t size, string *bytes) const;
    virtual bool Seal(const string &data, string *sealed) const;
    virtual bool Unseal(const string &sealed, string *data) const;
    virtual bool Quote(const string &data, string *signature) const;
    virtual bool VerifyQuote(const string &data, const string &signature) const;
    virtual bool Attest(string *attestation) const;
    virtual bool VerifyAttestation(const string &attestation) const;

  protected:
    // subclasses implement these methods for the underlying transport.
    virtual bool ReceiveMessage(google::protobuf::Message *m) const = 0;
    virtual bool SendMessage(const google::protobuf::Message &m) const = 0;
    
  private:
    virtual bool GetRPC(TaoChannelRPC *rpc) const;
    virtual bool SendRPC(const TaoChannelRPC &rpc) const;
    virtual bool GetResponse(TaoChannelResponse *resp) const;
    virtual bool SendResponse(const TaoChannelResponse &resp) const;
    bool SendAndReceiveData(const string &in, string *out, RPC rpc_type) const;
  };
} // namespace tao

#endif // TAO_TAO_CHANNEL_H_
