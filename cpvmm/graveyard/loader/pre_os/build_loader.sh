#!/bin/bash

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

# To run this script under Cygwin: Open Windows Command Prompt;
# execute: bash build_loader.sh.

load_base=0xa0000000
debug_port=0x03f8
evmm_mem_size=3

#############################################################################
# Find all files
#############################################################################

files=" \
    "./starter/chain_load.bin" \
    "./starter/starter.bin" \
    "./evmmh/evmmh.exe" \
    "../../bin/ms/release/startap.bin" \
    "../../bin/ms/release/evmm.bin" \
"

for x in $files; do
    if [ ! -f $x ]; then
        echo "  Can't find $x."
        exit
    fi
    cp $x .
done

../../tools/eficompress.exe ./evmm.bin ./evmm.bin.z

#############################################################################
# Convert text to hex
#############################################################################

function Dump()
{
  for t in $@; do
    x=$((t))
    x3=$((($x >> 24) & 0xff))
    x2=$((($x >> 16) & 0xff))
    x1=$((($x >>  8) & 0xff))
    x0=$((($x >>  0) & 0xff))
    y=$(printf "\\\x%02x\\\x%02x\\\x%02x\\\x%02x" $x0 $x1 $x2 $x3)
    printf $y
  done
}

#############################################################################
# EvmmDesc struct, each element is a uint32
#############################################################################

# File sizes in 512-byte blocks

s=$(stat -c%s "starter.bin")
StarterStart=2
StarterCount=$(((s + 511) / 512))

s=$(stat -c%s "evmmh.exe")
EvmmhStart=$((StarterStart + StarterCount))
EvmmhCount=$(((s + 511) / 512))

s=$(stat -c%s "startap.bin")
StartApStart=$((EvmmhStart + EvmmhCount))
StartApCount=$(((s + 511) / 512))

s=$(stat -c%s "evmm.bin.z")
EvmmStart=$((StartApStart + StartApCount))
EvmmCount=$(((s + 511) / 512))

StartDescStart=$((EvmmStart + EvmmCount))
StartDescCount=1

Guest0DescStart=$((StartDescStart + StartDescCount))
Guest0DescCount=1

# The Multiboot hader: offsets must match mem_map.h

MbMagic=0x1badb002
MbFlag=0x00010003
MbCksum=$((0 - MbMagic - MbFlag))
MbHdrAddr=$((load_base + 0x00000050))
MbText=$((load_base + 0x0000000))
MbBss=$((load_base + (Guest0DescStart + Guest0DescCount) * 512))
MbEnd=$MbBss
MbEntry=$((load_base + 0x00000400))

EvmmDesc=" \
    EvmmDescSize=80 \
    EvmmDescVer=0x00002000 \
    EvmmDescSectors=1 \
    UmbrSize=0 \
    EvmmMemMb=$evmm_mem_size \
    GuestCount=0 \
    EvmmlStart=0 \
    EvmmlCount=0 \
    StarterStart=$StarterStart \
    StarterCount=$StarterCount \
    EvmmhStart=$EvmmhStart \
    EvmmhCount=$EvmmhCount \
    StartApStart=$StartApStart \
    StartApCount=$StartApCount \
    EvmmStart=$EvmmStart \
    EvmmCount=$EvmmCount \
    StartDescStart=$StartDescStart \
    StartDescCount=$StartDescCount \
    Guest0DescStart=$Guest0DescStart \
    Guest0DescCount=$Guest0DescCount \
    MbMagic=$MbMagic \
    MbFlag=$MbFlag \
    MbCksum=$MbCksum \
    MbHdrAddr=$MbHdrAddr \
    MbText=$MbText \
    MbBss=$MbBss \
    MbEnd=$MbEnd \
    MbEntry=$MbEntry \
"

EvmmDesc=`echo $EvmmDesc | sed 's/[A-Za-z0-9]*=//g'`

#############################################################################
# StartDesc struct, each element is a uint32
#############################################################################

StartDesc=" \
    StartDescSizeVer=(0x00e0,0x0005) \
    StartDescInstCpuBootCpu=(0x0001,0x0000) \
    StartDescVmmGstsVmmStkPgs=(0x0000,0x000a) \
    StartDescVendor=0 \
    StartDescFlags=0 \
    StartDescDeviceOwner=0 \
    StartDescAcpiOwner=0 \
    StartDescNmiOwner=0 \
    StartDescMem00TotalSize=0 \
    StartDescMem00ImageSize=0 \
    StartDescMem00BaseAddrLow=0 \
    StartDescMem00BaseAddrHigh=0 \
    StartDescMem00EntryPointLow=0 \
    StartDescMem00EntryPointHigh=0 \
    StartDescMem01TotalSize=0 \
    StartDescMem01ImageSize=0 \
    StartDescMem01BaseAddrLow=0 \
    StartDescMem01BaseAddrHigh=0 \
    StartDescMem01EntryPointLow=0 \
    StartDescMem01EntryPointHigh=0 \
    StartDescE820LayoutLow=0 \
    StartDescE820LayoutHigh=0 \
    StartDescGuestState00Low=0 \
    StartDescGuestState00High=0 \
    StartDescGuestState01Low=0 \
    StartDescGuestState01High=0 \
    DebugVerbosity=0x00000004 \
    DebugReserved=0 \
    DebugPort00Type=0x01000101 \
    DebugPort00Base=$debug_port \
    DebugPort01Type=0 \
    DebugPort01Base=0x00000000 \
    DebugMaskLow=0xffffffff \
    DebugMaskHigh=0xffffffff \
    DebugBufferLow=0 \
    DebugBufferHigh=0 \
    ApicId00=0xffffffff \
    ApicId01=0xffffffff \
    ApicId02=0xffffffff \
    ApicId03=0xffffffff \
    ApicId04=0xffffffff \
    ApicId05=0xffffffff \
    ApicId06=0xffffffff \
    ApicId07=0xffffffff \
    ApicId08=0xffffffff \
    ApicId09=0xffffffff \
    ApicId10=0xffffffff \
    ApicId11=0xffffffff \
    ApicId12=0xffffffff \
    ApicId13=0xffffffff \
    ApicId14=0xffffffff \
    ApicId15=0xffffffff \
    ApicId16=0xffffffff \
    ApicId17=0xffffffff \
    ApicId18=0xffffffff \
    ApicId19=0xffffffff \
"

StartDesc=`echo $StartDesc | sed 's/(0x\(....\),0x\(....\))/0x\2\1/g'`
StartDesc=`echo $StartDesc | sed 's/[A-Za-z0-9]*=//g'`

#############################################################################
# GuestDesc struct, each emelemnt is a uint32
#############################################################################

GuestDesc=" \
    GuestDescSizeVer=(0x003c,0x0001) \
    GuestDescFlags=3 \
    GuestDescMagic=0 \
    GuestDescCpuAffinity=0xffffffff \
    GuestDescCpuStateCount=0 \
    GuestDescDeviceCount=0 \
    GuestDescImageSize=0 \
    GuestDescImageAddrHigh=0 \
    GuestDescImageAddrLow=0 \
    GuestDescPhyMemSize=0 \
    GuestDescImageOffsetGuestPhysical=0 \
    GuestDescCpuStateAddrHigh=0 \
    GuestDescCpuStateAddrLow=0 \
    GuestDescDeviceArrayAddrHigh=0 \
    GuestDescDeviceArrayAddrLow=0 \
"
GuestDesc=`echo $GuestDesc | sed 's/(0x\(....\),0x\(....\))/0x\2\1/g'`
GuestDesc=`echo $GuestDesc | sed 's/[A-Za-z0-9]*=//g'`

#############################################################################
# Build the loader binary
#############################################################################

Dump $EvmmDesc | dd of=loader.bin oflag=append seek=0
dd if=chain_load.bin of=loader.bin oflag=append seek=1
dd if=starter.bin of=loader.bin oflag=append seek=$StarterStart
dd if=evmmh.exe of=loader.bin oflag=append seek=$EvmmhStart
dd if=startap.bin of=loader.bin oflag=append seek=$StartApStart
dd if=evmm.bin.z of=loader.bin oflag=append seek=$EvmmStart
Dump $StartDesc | dd of=loader.bin oflag=append seek=$StartDescStart
Dump $GuestDesc | dd of=loader.bin oflag=append seek=$Guest0DescStart

# End of file
