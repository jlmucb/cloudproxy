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
class KvmVmFactory : public HostedProgramFactory {
 public:
  KvmVmFactory() : vm_connection_(nullptr) {}
  virtual ~KvmVmFactory();
  virtual bool Init();

  /// Compute the hash of a hosted program. The arguments are the same as the
  /// first three arguments of CreateHostedProgram.
  virtual bool HashHostedProgram(const string &name, const list<string> &args,
                                 string *child_hash) const;

  /// Start a virtual machine, using libvirt, from a set of arguments.
  /// @param name The name of the VM to create.
  /// @param args The arguments for VM creation. These must have the following
  /// values:
  ///   1. a path to a template file like run/vm.xml
  ///   2. path to the kernel to boot
  ///   3. path to the initrd for this kernel
  ///   4. path to the disk image
  /// All of these arguments must be readable by libvirt-kvm.
  /// @param child_hash The hash of the hosted program.
  /// @param parent_channel The channel to use for establishing communication
  /// with the hosted program.
  /// @param[out] identifier An identifier for the hosted program: in this
  /// case, it's the name of the VM.
  virtual bool CreateHostedProgram(const string &name, const list<string> &args,
                                   const string &child_hash,
                                   TaoChannel &parent_channel,
                                   string *identifier) const;

  /// Get the name of this factory type: KvmVmFactory.
  virtual string GetFactoryName() const;

 private:
  // A libvirt-supplied connection used to start and connect to VMs.
  virConnectPtr vm_connection_;
  DISALLOW_COPY_AND_ASSIGN(KvmVmFactory);
};
}  // namespace tao

#endif  // TAO_KVM_VM_FACTORY_H_
