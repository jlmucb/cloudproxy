#include "pipe_tao_channel.h"

#include <glog/logging.h>

#include <stdlib.h>
#include <errno.h>

extern int errno;

namespace tao {

  bool PipeTaoChannel::ExtractPipes(int *argc, char ***argv, int fds[2]) {
    CHECK_NOTNULL(argc);
    CHECK_NOTNULL(argv);
    CHECK_NOTNULL(fds);
    
    if (*argc < 3) {
      LOG(ERROR) << "Not enough arguments to extract the pipes";
      return false;
    }

    errno = 0;
    fds[0] = strtol(*argv[*argc - 2], NULL, 0);
    if (errno != 0) {
      LOG(ERROR) << "Could not convert the second-to-last argument to an integer";
      return false;
    }

    errno = 0;
    fds[1] = strtol(*argv[*argc - 1], NULL, 0);
    if (errno != 0) {
      LOG(ERROR) << "Could not convert the last argument to an integer";
      return false;
    }

    // clean up argc and argv
    // TODO(tmroeder): do I need to free the memory here?
    *argc = *argc - 2;
    *argv[*argc] = NULL;
    return true;
  }

  PipeTaoChannel::PipeTaoChannel(int fds[2])
    : readfd_(fds[0]),
      writefd_(fds[1]) {
    // the file descriptors are assumed to be open already
  }

  PipeTaoChannel::~PipeTaoChannel() {
    close(readfd_);
    close(writefd_);
  }

  bool PipeTaoChannel::GetRPC(TaoChannelRPC *rpc) {
    CHECK_NOTNULL(rpc);
    return rpc->ParseFromFileDescriptor(readfd_);
  }

  bool PipeTaoChannel::SendRPC(const TaoChannelRPC &rpc) {
    return rpc.SerializeToFileDescriptor(writefd_);
  }

  bool PipeTaoChannel::GetResponse(TaoChannelResponse *resp) {
    CHECK_NOTNULL(resp);
    return resp->ParseFromFileDescriptor(readfd_);
  }

  bool PipeTaoChannel::SendResponse(const TaoChannelResponse &resp) {
    return resp.SerializeToFileDescriptor(writefd_);
  }
} // namespace tao
