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
# Copyright 2001-2013 Intel Corporation All Rights Reserved.
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

This readme covers how to setup the build environment and instructions 
on how to build eVMM binaries for the Cloudproxy version.

=============================================================================
Build environment
=============================================================================

(1) We used Windows 7 64-bit as our build system
(2) Install Visual Studio 2010.
(3) Install ActivePerl.
(4) Install Cygwin.
    * Select the following options: "make" and "binutils" from the Devel 
      Default menu.
    * Add "c:\cygwin\bin" to the PATH environment variable.
    * Verify that "c:\cygwin\bin" is after perl directories in "PATH".
    * Verify GNU Make version is 3.81 or newer (type "make -v").

=============================================================================
Building eVmm binaries
=============================================================================

(1) cd to eVmm folder. 

    c:\eVmm> make config_release

    or 

    c:\eVmm> make config_debug

    * The command is optional (default is release)
    * Does not build any binaries

(2) Building eVmm binaries

    c:\eVmm> make all [-j[jobs], --jobs[=jobs]]

    This ceates "evmm.bin" and "startap.bin" in c:\eVmm\bin\ms folder.

=============================================================================
Known problems
=============================================================================

(1) Dependency on *.h is not checked. Use "make clean" before rebuilding 
after modification of any header file. 

End of file
