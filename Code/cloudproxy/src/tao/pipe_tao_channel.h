#ifndef TAO_PIPE_TAO_CHANNEL_H_
#define TAO_PIPE_TAO_CHANNEL_H_

#include <tao/tao_channel.h>

namespace tao {
  // a TaoChannel that communicates over a pair of file descriptors
  // set up with pipe(2)
  class PipeTaoChannel : public TaoChannel {
  public:
    // the PipeTaoChannel expects its pipe file descriptors as the
    // last two arguments. It modifies argc and argv to remove these
    // file descriptors from the arguments.
    static bool ExtractPipes(int *argc, char ***argv, int fds[2]);

    PipeTaoChannel(int fds[2]);
    virtual ~PipeTaoChannel();

  protected:
    virtual bool ReceiveMessage(google::protobuf::Message *m) const;
    virtual bool SendMessage(const google::protobuf::Message &m) const;

  private:
    int readfd_;
    int writefd_;
  };
}

#endif // TAO_PIPE_TAO_CHANNEL_H_
