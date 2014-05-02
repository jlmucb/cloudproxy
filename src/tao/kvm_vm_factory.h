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

#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN
#include <libvirt/libvirt.h>

#include "tao/hosted_program_factory.h"

using std::list;
using std::string;

namespace tao {
/// A class that creates virtual machine guest OSes using KVM, libvirt, and
/// qemu. It needs to be passed a template XML file like the one in run/vm.xml,
/// and it expects the template it gets to have the same number of slots (%s) as
/// the one currently checked in to run/vm.xml.
/// The path for the virtual machine is simply an opaque name.
/// The args contain the following values:
///   args[0] - a path to a template file like run/vm.xml
///   args[1] - path to the kernel to boot
///   args[2] - path to the initrd for this kernel
///   args[3] - path to the disk image
/// All of these arguments must be readable by libvirt-kvm.
class KvmVmFactory : public HostedProgramFactory {
 public:
  KvmVmFactory() : vm_connection_(nullptr) {}
  virtual ~KvmVmFactory();
  virtual bool Init();

  virtual bool GetHostedProgramTentativeName(
      int id, const string &path, const list<string> &args,
      string *tentative_child_name) const;

  virtual bool CreateHostedProgram(int id, const string &name,
                                   const list<string> &args,
                                   const string &tentative_child_name,
                                   TaoChannel *parent_channel,
                                   string *child_name) const;

  virtual string GetFactoryName() const;

  virtual bool ParseChildName(string child_name, int *id, string *path,
                              string *prog_hash, string *arg_hash, string *pid,
                              string *subprin) const;

 protected:
  virtual string CreateChildName(int id, const string &path,
                                 const string &prog_hash,
                                 const string &arg_hash, string pid) const;

 private:
  // A libvirt-supplied connection used to start and connect to VMs.
  virConnectPtr vm_connection_;
  DISALLOW_COPY_AND_ASSIGN(KvmVmFactory);
};
}  // namespace tao

#endif  // TAO_KVM_VM_FACTORY_H_
