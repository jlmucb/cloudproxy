#############################################################################
# Copyright (c) 2013 Intel Corporation
#
#   John Manferdelli
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


OBJROOT=~/jlmcrypt
make_vars= TARGET_MACHINE_TYPE=x86

BUILD_TARGETS= keyNegoServer tcService fileServer fileClient cryptUtility cryptotest aesspeed rsaspeedtest tcLaunch
TARGETS=$(BUILD_TARGETS) clean

.PHONY: $(TARGETS)

all: $(BUILD_TARGETS)

tcService:
	$(MAKE) -C tcService -f tcService.mak

clean:
	rm -f $(OBJROOT)/vmmobjects/*.o

.PHONY: vmm startap clean

