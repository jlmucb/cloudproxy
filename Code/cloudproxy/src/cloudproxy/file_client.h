//  File: file_client.h
//  Author: Tom Roeder <tmroeder@google.com>
//
// Description: The FileClient class interacts with FileServer
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

#ifndef CLOUDPROXY_FILE_CLIENT_H_
#define CLOUDPROXY_FILE_CLIENT_H_

#include "cloudproxy/cloud_client.h"

namespace cloudproxy {
class FileClient : public CloudClient {
 public:

  FileClient(const string &file_path, const string &tls_cert,
             const string &tls_key, const string &tls_password,
             const string &public_policy_keyczar,
             const string &public_policy_pem, const string &whitelist_location,
             const string &server_addr, ushort server_port);

  virtual ~FileClient() {}

  // Sends a CREATE request to the attached CloudServer
  virtual bool Create(const string &owner, const string &object_name);

  // Sends a DESTROY request to the attached CloudServer
  virtual bool Destroy(const string &owner, const string &object_name);

  // Send a READ request to a CloudServer
  virtual bool Read(const string &requestor, const string &object_name,
                    const string &output_name);

  // Sends a WRITE request to a CloudServer
  virtual bool Write(const string &requestor, const string &input_name,
                     const string &object_name);

 private:

  // the base path for files that are read from and written to the server
  string file_path_;
};
}

#endif  // CLOUDPROXY_FILE_CLIENT_H_
