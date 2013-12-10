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

#include <glog/logging.h>
#include <libvirt/virterror.h>
#include <keyczar/base/scoped_ptr.h>

#include "tao/kvm_unix_tao_channel_params.pb.h"
#include "tao/tao_channel.h"

namespace {
const char *vm_template =
"<domain type='kvm' xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'>\n"
"  <name>%s</name>\n"
"  <memory>1048576</memory>\n"
"  <currentMemory>1048576</currentMemory>\n"
"  <vcpu>1</vcpu>\n"
"  <os>\n"
"    <type arch='x86_64' machine='pc-1.0'>hvm</type>\n"
"    <kernel>%s</kernel>\n"
"    <initrd>%s</initrd>\n"
"    <boot dev='hd'/>\n"
"  </os>\n"
"  <features>\n"
"    <acpi/>\n"
"    <apic/>\n"
"    <pae/>\n"
"  </features>\n"
"  <clock offset='utc'/>\n"
"  <on_poweroff>destroy</on_poweroff>\n"
"  <on_reboot>destroy</on_reboot>\n"
"  <on_crash>restart</on_crash>\n"
"  <devices>\n"
"    <emulator>/usr/bin/kvm</emulator>\n"
"    <disk type='file' device='disk'>\n"
"      <driver name='qemu' type='raw'/>\n"
"      <source file='%s'/>\n"
"      <target dev='sda' bus='sata'/>\n"
"      <address type='drive' controller='0' bus='0' unit='0'/>\n"
"    </disk>\n"
"    <controller type='ide' index='0'>\n"
"      <address type='pci' domain='0x0000' bus='0x00' slot='0x01' function='0x1'/>\n"
"    </controller>\n"
"    <controller type='sata' index='0'>\n"
"      <address type='pci' domain='0x0000' bus='0x00' slot='0x06' function='0x0'/>\n"
"    </controller>\n"
"    <interface type='network'>\n"
"      <mac address='52:54:00:82:22:a8'/>\n"
"      <source bridge='default'/>\n"
"      <address type='pci' domain='0x0000' bus='0x00' slot='0x03' function='0x0'/>\n"
"    </interface>\n"
"    <serial type='unix'>\n"
"      <source mode='bind' path='%s'/>\n"
"      <target port='0'/>\n"
"    </serial>\n"
"    <console type='unix'>\n"
"      <source mode='bind' path='%s'/>\n"
"      <target type='serial' port='0'/>\n"
"    </console>\n"
"    <input type='mouse' bus='ps2'/>\n"
"    <graphics type='vnc' port='-1' autoport='yes'/>\n"
"    <sound model='ac97'>\n"
"      <address type='pci' domain='0x0000' bus='0x00' slot='0x04' function='0x0'/>\n"
"    </sound>\n"
"    <video>\n"
"      <model type='cirrus' vram='9216' heads='1'/>\n"
"      <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x0'/>\n"
"    </video>\n"
"    <memballoon model='virtio'>\n"
"      <address type='pci' domain='0x0000' bus='0x00' slot='0x05' function='0x0'/>\n"
"    </memballoon>\n"
"  </devices>\n"
"  <qemu:commandline>\n"
"    <qemu:arg value='-s'/>\n"
"  </qemu:commandline>\n"
"</domain>\n";
}

namespace tao {
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

bool KvmVmFactory::CreateHostedProgram(const string &name,
                                       const list<string> &args,
                                       const string &child_hash,
                                       TaoChannel &parent_channel) const {
  if (args.size() != 3) {
    LOG(ERROR) << "Invalid parameters to KvmVmFactory::CreateHostedProgram";
    return false;
  }

  string params;
  if (!parent_channel.AddChildChannel(child_hash, &params)) {
    LOG(ERROR) << "Could not add the child channel for this VM";
    return false;
  }

  // The params have to be a KvmUnixTaoChannelParams and must specify a path for
  // the connection to the client.
  KvmUnixTaoChannelParams kutcp;
  if (!kutcp.ParseFromString(params)) {
    LOG(ERROR) << "Could not parse the params as a KvmUnixTaoChannelParams";
    return false;
  }

  string path(kutcp.unix_socket_path());

  auto it = args.begin();
  string kernel(*(it++));
  string initrd(*(it++));
  string disk(*(it++));

  // Each parameter replaces a string of the form '%s', so the contribution of
  // each is .size() - 2. The final + 1 is due to the final null byte.
  size_t formatted_size = strlen(vm_template) + name.size() - 2 +
      kernel.size() - 2 + initrd.size() - 2 + disk.size() - 2 +
      2 * (path.size() - 2) + 1;

  scoped_array<char> buf(new char[formatted_size]);
  int count = snprintf(buf.get(), formatted_size, vm_template,
                       name.c_str(), kernel.c_str(), initrd.c_str(),
                       disk.c_str(), path.c_str(), path.c_str());

  if (count < 0) {
    PLOG(ERROR) << "Could not snprintf into the buffer";
    return false;
  }

  // This cast is safe, since we know that count >= 0
  if (static_cast<size_t>(count) != formatted_size) {
    LOG(ERROR) << "Could not print the right number of characters into the "
               << "buffer. Expected " << (int)formatted_size << " and "
               << "printed " << count;
    return false;
  }

  virDomainPtr vm_domain_ = virDomainCreateXML(vm_connection_, buf.get(), 0);
  if (!vm_domain_) {
    LOG(ERROR) << "Could not create a VM using the supplied parameters";
    virError *err = virGetLastError();
    if (err) {
      LOG(ERROR) << "The error from libvirt was " << err->message;
    }

    return false;
  }

  LOG(INFO) << "Created a VM with name " << name;
  return true;
}

string KvmVmFactory::GetFactoryName() const { return "KvmVmFactory"; }
}  // namespace tao
