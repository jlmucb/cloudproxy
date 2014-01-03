//  File: kvm_vm_factory.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An implementation of the hosted program factory that creates
//  KVM virtual machines using libvirt.
//
//  Copyright (c) 2013, Google Inc.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "tao/kvm_vm_factory.h"

#include <unistd.h>

#include <fstream>
#include <sstream>

#include <glog/logging.h>
#include <keyczar/base/base64w.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/crypto_factory.h>
#include <keyczar/keyczar.h>
#include <libvirt/virterror.h>

#include "tao/kvm_unix_tao_channel_params.pb.h"
#include "tao/kvm_unix_tao_child_channel.h"
#include "tao/tao_child_channel_params.pb.h"
#include "tao/tao_channel.h"
#include "tao/util.h"

using keyczar::base::Base64WDecode;
using keyczar::CryptoFactory;
using keyczar::MessageDigestImpl;

using std::ifstream;
using std::stringstream;

namespace tao {
KvmVmFactory::~KvmVmFactory() {
  if (vm_connection_ != nullptr) {
    virConnectClose(vm_connection_);
  }
}

bool KvmVmFactory::Init() {
  // KvmVmFactory needs a QEMU connection
  vm_connection_ = virConnectOpen("qemu:///system");
  if (!vm_connection_) {
    LOG(ERROR) << "Could not connect to QEMU for VM creation";
    virError *err = virGetLastError();
    if (err) {
      LOG(ERROR) << "The error from libvirt was " << err->message;
    }

    return false;
  }

  return true;
}

// The hash of the VM is Base64(H(H(template) || H(name) || H(kernel) ||
//                                H(initrd)))
bool KvmVmFactory::HashHostedProgram(const string &name,
                                     const list<string> &args,
                                     string *child_hash) const {
  // As in CreateHostedProgram, we have to make sure that we have the right
  // number of arguments for our operations to make sense.
  // The extra argument in this case is the child channel creation parameters
  // passed from the Tao.
  if (args.size() != 4) {
    LOG(ERROR) << "Wrong number of arguments. Expected 4 arguments, but got "
               << (int)args.size();
    return false;
  }

  auto it = args.begin();
  string vm_template(*(it++));
  string kernel(*(it++));
  string initrd(*(it++));
  // The next argument is the disk, but it is ignored, since it's untrusted.

  ifstream vm_template_file(vm_template.c_str());
  if (!vm_template_file) {
    LOG(ERROR) << "Could not open the VM template file " << vm_template_file;
    return false;
  }

  stringstream vm_template_stream;
  vm_template_stream << vm_template_file.rdbuf();

  ifstream kernel_file(kernel.c_str());
  if (!kernel_file) {
    LOG(ERROR) << "Could not open the kernel file " << kernel;
    return false;
  }

  stringstream kernel_stream;
  kernel_stream << kernel_file.rdbuf();

  ifstream initrd_file(initrd.c_str());
  if (!initrd_file) {
    LOG(ERROR) << "Could not open the initrd file " << initrd;
    return false;
  }

  stringstream initrd_stream;
  initrd_stream << initrd_file.rdbuf();

  return HashVM(vm_template_stream.str(), name, kernel_stream.str(),
                initrd_stream.str(), child_hash);
}

bool KvmVmFactory::CreateHostedProgram(const string &name,
                                       const list<string> &args,
                                       const string &child_hash,
                                       TaoChannel &parent_channel) const {
  if (args.size() != 5) {
    LOG(ERROR) << "Invalid parameters to KvmVmFactory::CreateHostedProgram";
    return false;
  }

  auto it = args.begin();
  string vm_template(*(it++));
  string kernel(*(it++));
  string initrd(*(it++));
  string disk(*(it++));
  string encoded_params(*(it++));

  // The params have to be a Base64W-encoded KvmUnixTaoChannelParams and must
  // specify a path for the connection to the client.
  string params;
  if (!Base64WDecode(encoded_params, &params)) {
    LOG(ERROR) << "Could not decode the encoded params";
    return false;
  }

  TaoChildChannelParams tccp;
  if (!tccp.ParseFromString(params)) {
    LOG(ERROR) << "Could not parse the TaoChildChannelParams from the params";
    return false;
  }

  if (tccp.channel_type().compare(KvmUnixTaoChildChannel::ChannelType())) {
    LOG(ERROR) << "Invalid params type: expected "
               << KvmUnixTaoChildChannel::ChannelType() << " but got "
               << tccp.channel_type();
    return false;
  }

  KvmUnixTaoChannelParams kutcp;
  if (!kutcp.ParseFromString(tccp.params())) {
    LOG(ERROR) << "Could not parse the params as a KvmUnixTaoChannelParams";
    return false;
  }

  string path(kutcp.guest_device());

  ifstream vm_template_file(vm_template.c_str());
  if (!vm_template_file) {
    LOG(ERROR) << "Could not open the VM template file " << vm_template_file;
    return false;
  }

  stringstream vm_template_stream;
  vm_template_stream << vm_template_file.rdbuf();
  string vmspec(vm_template_stream.str());

  // The final + 1 is due to the final null byte. This is larger than needed,
  // since snprintf removes the %s that gets replaced each time.
  size_t formatted_size =
      vmspec.size() + name.size() + kernel.size() + initrd.size() +
      encoded_params.size() + disk.size() + path.size() + 1;

  scoped_array<char> buf(new char[formatted_size]);
  int count = snprintf(buf.get(), formatted_size, vmspec.c_str(), name.c_str(),
                       kernel.c_str(), initrd.c_str(), encoded_params.c_str(),
                       disk.c_str(), path.c_str());

  if (count < 0) {
    PLOG(ERROR) << "Could not snprintf into the buffer";
    return false;
  }

  // This cast is safe, since we know that count >= 0
  if (static_cast<size_t>(count) > formatted_size) {
    LOG(ERROR) << "Could not print the right number of characters into the "
               << "buffer. Expected " << (int)formatted_size << " and "
               << "printed " << count;
    return false;
  }

  // Sanity check the files to make sure they exist before trying to start the
  // domain, since libvirt crashes when passed invalid files this way.
  if (access(kernel.c_str(), F_OK)) {
    PLOG(ERROR) << "Could not access the kernel file " << kernel;
    return false;
  }

  if (access(initrd.c_str(), F_OK)) {
    PLOG(ERROR) << "Could not access the initrd file " << initrd;
    return false;
  }

  if (access(disk.c_str(), F_OK)) {
    PLOG(ERROR) << "Could not access the disk file " << disk;
    return false;
  }

  virDomainPtr vm_domain = virDomainCreateXML(vm_connection_, buf.get(), 0);
  if (!vm_domain) {
    LOG(ERROR) << "Could not create a VM using the supplied parameters";
    virError *err = virGetLastError();
    if (err) {
      LOG(ERROR) << "The error from libvirt was " << err->message;
    }

    return false;
  }

  // Find out which /dev/pts entry was used in the host.
  char *new_xml = virDomainGetXMLDesc(vm_domain, 0);
  if (!new_xml) {
    LOG(ERROR) << "Could not get the XML for the newly created domain";
    return false;
  }

  string new_xml_str(new_xml);
  free(new_xml);

  size_t pts_start = new_xml_str.find("/dev/pts/");
  if (pts_start == string::npos) {
    LOG(ERROR) << "Could not find a /dev/pts entry in the domain XML";
    return false;
  }

  size_t pts_end = new_xml_str.find_first_of("'", pts_start);
  if (pts_end == string::npos) {
    LOG(ERROR) << "Invalid XML";
    return false;
  }

  string local_device(new_xml_str.substr(pts_start, pts_end - pts_start));
  LOG(INFO) << "Created a VM with name " << name;

  // The parent channel will connect to the local device now.
  if (!parent_channel.UpdateChildParams(child_hash, local_device)) {
    LOG(ERROR) << "Could not update the child parameters";
    return false;
  }

  return true;
}

string KvmVmFactory::GetFactoryName() const { return "KvmVmFactory"; }
}  // namespace tao
