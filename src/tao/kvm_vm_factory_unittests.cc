//  File: kvm_vm_factory_unittests.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Tests the basic VM creation facility.
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

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <keyczar/base/base64w.h>
#include <libvirt/libvirt.h>

#include "tao/fake_tao.h"
#include "tao/fake_tao_channel.h"
#include "tao/kvm_unix_tao_channel.h"
#include "tao/kvm_vm_factory.h"
#include "tao/util.h"

using keyczar::base::Base64WEncode;

using tao::FakeTao;
using tao::FakeTaoChannel;
using tao::KvmVmFactory;
using tao::KvmUnixTaoChannel;
using tao::ScopedTempDir;

DEFINE_string(vm_template, "../run/vm.xml", "The location of a VM template");
DEFINE_string(kernel_file, "/tmp/vmlinuz-3.7.5", "The location of the kernel");
DEFINE_string(initrd_file, "/tmp/initrd-3.7.5", "The location of the initrd");
DEFINE_string(disk_file, "/temp/vm.img", "The location of a disk image");

class KvmVmFactoryTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    // Get a temporary directory to use for the files.
    string dir_template("/tmp/kvm_unix_tao_test_XXXXXX");
    scoped_array<char> temp_name(new char[dir_template.size() + 1]);
    memcpy(temp_name.get(), dir_template.data(), dir_template.size() + 1);

    ASSERT_TRUE(mkdtemp(temp_name.get()));
    temp_dir_.reset(new string(temp_name.get()));

    creation_socket_ = *temp_dir_ + string("/creation_socket");
    stop_socket_ = *temp_dir_ + string("/stop_socket");

    channel_.reset(new KvmUnixTaoChannel(creation_socket_, stop_socket_));

    child_hash_ = "Fake hash";
    ASSERT_TRUE(channel_->AddChildChannel(child_hash_, &params_))
      << "Could not create the channel for the child";

    ASSERT_TRUE(Base64WEncode(params_, &encoded_params_))
      << "Could not encode the parameters";

    factory_.reset(new KvmVmFactory());
    ASSERT_TRUE(factory_->Init()) << "Could not initialize the factory";
  }

  scoped_ptr<KvmUnixTaoChannel> channel_;
  scoped_ptr<KvmVmFactory> factory_;
  ScopedTempDir temp_dir_;
  string creation_socket_;
  string stop_socket_;
  string params_;
  string encoded_params_;
  string child_hash_;
};

TEST_F(KvmVmFactoryTest, HashTest) {
  list<string> args;
  args.push_back(FLAGS_vm_template);
  args.push_back(FLAGS_kernel_file);
  args.push_back(FLAGS_initrd_file);
  args.push_back(FLAGS_disk_file);
  string new_hash;
  EXPECT_TRUE(factory_->HashHostedProgram("test", args, &new_hash))
    << "Could not hash the program";
}

TEST_F(KvmVmFactoryTest, CreationTest) {
  list<string> args;
  args.push_back(FLAGS_vm_template);
  args.push_back(FLAGS_kernel_file);
  args.push_back(FLAGS_initrd_file);
  args.push_back(FLAGS_disk_file);
  args.push_back(encoded_params_);
  EXPECT_TRUE(factory_->CreateHostedProgram("test", args, child_hash_,
                                            *channel_))
    << "Could not create a vm";

  virConnectPtr conn = virConnectOpen("qemu:///system");
  ASSERT_TRUE(conn) << "Could not connect to QEMU";

  virDomainPtr dom = virDomainLookupByName(conn, "test");
  ASSERT_TRUE(dom) << "Could not find the domain named 'test'";
  EXPECT_EQ(virDomainDestroy(dom), 0) << "Could not shut down the VM";

  // The value 1 is expected here because virConnectClose returns the remaining
  // reference count on this connection, and the KvmVmFactory is holding another
  // connection.
  EXPECT_EQ(virConnectClose(conn), 1) << "Could not close the QEMU connection";
}
