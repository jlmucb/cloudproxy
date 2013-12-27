#############################################################################
# Copyright (c) 2013 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#############################################################################

#############################################################################
# INTEL CONFIDENTIAL
# Copyright 2013 Intel Corporation All Rights Reserved.
#
# The source code contained or described herein and all documents related to
# the source code ("Material") are owned by Intel Corporation or its
# suppliers or licensors.  Title to the Material remains with Intel
# Corporation or its suppliers and licensors.  The Material contains trade
# secrets and proprietary and confidential information of Intel or its
# suppliers and licensors.  The Material is protected by worldwide copyright
# and trade secret laws and treaty provisions.  No part of the Material may
# be used, copied, reproduced, modified, published, uploaded, posted,
# transmitted, distributed, or disclosed in any way without Intel's prior
# express written permission.
#
# No license under any patent, copyright, trade secret or other intellectual
# property right is granted to or conferred upon you by disclosure or
# delivery of the Materials, either expressly, by implication, inducement,
# estoppel or otherwise.  Any license under such intellectual property rights
# must be express and approved by Intel in writing.
#############################################################################

=============================================================================
Creating eVmm USB boot disk
=============================================================================

(1) Install grub on a USB flash drive

    On a Linux machine

    a. Insert a USB flash drive to the Linux machine. The USB flash drive 
       is usually /dev/sdb mounted at /media/[uuid]/

    b. Execute the following command

       # sudo mkdir /media/[uuid]/boot
       # grub-install --force --boot-directory=/media/[uuid]/boot /dev/sdb
        
    c. Create a grub.cfg file with the following content:

        menuentry "Windows" {
            set root=(hd1)
            chainloader +1
        }
        menuentry "eVmm" {
            multiboot /loader.bin
        }

        where "Windows" is the guest OS.

    d. Copy grub.cfg to /media/[uuid]/boot/grub

(2) Building eVmm loader

    On the target machine where eVmm is to be installed

    a. Boot the system from the USB drive

    b. When grub boot menu appears, press 'c' to grub command line and type
       the following command:

       # lsmmap 
  
    c. Find a memory region not reserved (usually 0xa0000000). This will be 
       used as the load_base address of eVmm. Update the load_base in 
       build_loader.sh file in the package to use this address.

    On a build machine (Windows machine)

    d. Build startap.bin and evmm.bin (eVmm/readme.txt)

    e. Build the eVmm loader

       c:\eVmm\loader\pre_os> make

       The output loader binary, loader.bin, can be found from the same 
       directory

    f. Copy loader.bin to the root directory of the USB drive

=============================================================================
Running eVmm and guest OS
=============================================================================

On the target machine, 

(1) Boot the target machine from the USB drive. At the grub menu, 
    select "eVmm"

(2) Once eVmm is running, grub menu will appear again. Now select the 
    desired guest OS (e.g. Windows)


# End of file
