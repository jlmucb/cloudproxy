//  File: pipe_tao_channel.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: PipeTaoChannel implements Tao communication over file
//  descriptors
//
//  Copyright (c) 2013, Google Inc.  All rights reserved.
//
// Use, duplication and disclosure of this file and derived works of
// this file are subject to and licensed under the Apache License dated
// January, 2004, (the "License").  This License is contained in the
// top level directory originally provided with the CloudProxy Project.
// Your right to use or distribute this file, or derived works thereof,
// is subject to your being bound by those terms and your use indicates
// consent to those terms.
//
// If you distribute this file (or portions derived therefrom), you must
// include License in or with the file and, in the event you do not include
// the entire License in the file, the file must contain a reference
// to the location of the License.

// ------------------------------------------------------------------------

#ifndef TAO_PIPE_TAO_CHANNEL_H_
#define TAO_PIPE_TAO_CHANNEL_H_

#include <keyczar/keyczar.h>
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

    DISALLOW_COPY_AND_ASSIGN(PipeTaoChannel);
  };
}

#endif // TAO_PIPE_TAO_CHANNEL_H_
