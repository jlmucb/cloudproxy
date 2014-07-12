# Copyright 2014 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set(SD src)
set(ISD include)

set(MODP_SOURCES
    ${SD}/modp_b64w.c
   )

set(MODP_HEADERS
    ${SD}/modp_b64w_data.h
    ${ISD}/modp/modp_b64w.h
   )

include_directories(${ISD}/modp)
add_library(modp STATIC ${MODP_SOURCES} ${MODP_HEADERS})
