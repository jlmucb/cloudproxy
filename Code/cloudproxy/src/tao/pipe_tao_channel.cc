#include "tao/pipe_tao_channel.h"

#include <glog/logging.h>
#include <keyczar/base/scoped_ptr.h>

#include <stdlib.h>
#include <errno.h>

extern int errno;

namespace tao {

  bool PipeTaoChannel::ExtractPipes(int *argc, char ***argv, int fds[2]) {
    CHECK_NOTNULL(argc);
    CHECK_NOTNULL(argv);
    CHECK_NOTNULL(fds);
    
    LOG(INFO) << "Establishing the Tao Channel";

    if (*argc < 3) {
      LOG(ERROR) << "Not enough arguments to extract the pipes";
      return false;
    }
    LOG(INFO) << "We have the right number of arguments. *argc = " << *argc;
    LOG(INFO) << "argv = " << argv;
    LOG(INFO) << "*argv = " << *argv;

    errno = 0;
    fds[0] = strtol((*argv)[*argc - 2], NULL, 0);
    if (errno != 0) {
      LOG(ERROR) << "Could not convert the second-to-last argument to an integer";
      return false;
    }

    LOG(INFO) << "Got fds[0] = " << fds[0];

    errno = 0;
    fds[1] = strtol((*argv)[*argc - 1], NULL, 0);
    if (errno != 0) {
      LOG(ERROR) << "Could not convert the last argument to an integer";
      return false;
    }
    LOG(INFO) << "Got fds[1] = " << fds[1];

    // clean up argc and argv
    // TODO(tmroeder): do I need to free the memory here?
    *argc = *argc - 2;
    (*argv)[*argc] = NULL;
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

  bool PipeTaoChannel::ReceiveMessage(google::protobuf::Message *m) const {
    // try to receive an integer
    CHECK_NOTNULL(m);
    size_t len;
    ssize_t bytes_read = read(readfd_, &len, sizeof(size_t));
    if (bytes_read != sizeof(size_t)) {
      LOG(ERROR) << "Could not receive a size on the channel";
      return false;
    }

    // then read this many bytes as the message
    scoped_array<char> bytes(new char[len]);
    bytes_read = read(readfd_, bytes.get(), len);

    // TODO(tmroeder): add safe integer library
    if (bytes_read != static_cast<ssize_t>(len)) {
      LOG(ERROR) << "Could not read the right number of bytes from the fd";
      return false;
    }

    string serialized(bytes.get(), len);
    return m->ParseFromString(serialized);
  }

  bool PipeTaoChannel::SendMessage(const google::protobuf::Message &m) const {
    // send the length then the serialized message
    string serialized;
    if (!m.SerializeToString(&serialized)) {
      LOG(ERROR) << "Could not serialize the Message to a string";
      return false;
    }

    size_t len = serialized.size();
    ssize_t bytes_written = write(writefd_, &len, sizeof(size_t));
    if (bytes_written != sizeof(size_t)) {
      LOG(ERROR) << "Could not write the length to the fd";
      return false;
    }

    bytes_written = write(writefd_, serialized.data(), len);
    if (bytes_written != static_cast<ssize_t>(len)) {
      LOG(ERROR) << "Could not wire the serialized message to the fd";
      return false;
    }
    
    return true;
  }

} // namespace tao
