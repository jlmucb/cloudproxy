//  File: kvm_vm_factory.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A factory that creates KVM-based virtual machines.
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

#ifndef TAO_KVM_VM_FACTORY_H_
#define TAO_KVM_VM_FACTORY_H_

#include <list>
#include <string>

#include <keyczar/base/basictypes.h> // DISALLOW_COPY_AND_ASSIGN
#include <libvirt/libvirt.h>

#include "tao/hosted_program_factory.h"

using std::list;
using std::string;

namespace tao {
class KvmVmFactory : public HostedProgramFactory {
 public:
  KvmVmFactory() {}
  virtual ~KvmVmFactory() {}
  virtual bool Init();

  virtual bool HashHostedProgram(const string &name, const list<string> &args,
                                 string *child_hash) const;

  // @param name The name of the VM to create
  // @param args The arguments for VM creation. These must have the following
  // values:
  //   1. path to the kernel to boot
  //   2. path to the initrd for this kernel
  //   3. path to the disk image
  // @param child_hash The hash of the hosted program
  // @param parent_channel The channel to use for establishing communication
  // with the hosted program.
  virtual bool CreateHostedProgram(const string &name, const list<string> &args,
                                   const string &child_hash,
                                   TaoChannel &parent_channel) const;
  virtual string GetFactoryName() const;

 private:
  virConnectPtr vm_connection_;
  DISALLOW_COPY_AND_ASSIGN(KvmVmFactory);
};
}  // namespace tao

#endif  // TAO_KVM_VM_FACTORY_H_
