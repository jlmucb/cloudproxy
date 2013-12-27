/****************************************************************************
* Copyright (c) 2013 Intel Corporation
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0

* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
****************************************************************************/

/****************************************************************************
* INTEL CONFIDENTIAL
* Copyright 2001-2013 Intel Corporation All Rights Reserved.
*
* The source code contained or described herein and all documents related to
* the source code ("Material") are owned by Intel Corporation or its
* suppliers or licensors.  Title to the Material remains with Intel
* Corporation or its suppliers and licensors.  The Material contains trade
* secrets and proprietary and confidential information of Intel or its
* suppliers and licensors.  The Material is protected by worldwide copyright
* and trade secret laws and treaty provisions.  No part of the Material may
* be used, copied, reproduced, modified, published, uploaded, posted,
* transmitted, distributed, or disclosed in any way without Intel's prior
* express written permission.
*
* No license under any patent, copyright, trade secret or other intellectual
* property right is granted to or conferred upon you by disclosure or
* delivery of the Materials, either expressly, by implication, inducement,
* estoppel or otherwise.  Any license under such intellectual property rights
* must be express and approved by Intel in writing.
****************************************************************************/

#ifndef _IDT_H_
#define _IDT_H_

/*-------------------------------------------------------*
*  FUNCTION     : hw_idt_register_handler()
*  PURPOSE      : Register interrupt handler at spec. vector
*  ARGUMENTS    : UINT8 vector_id
*               : ADDRESS handler - address of function
*  RETURNS      : void
*-------------------------------------------------------*/
void hw_idt_register_handler(
    VECTOR_ID   vector_id,
    ADDRESS     isr_handler_address);

/*-------------------------------------------------------*
*  FUNCTION     : hw_idt_load()
*  PURPOSE      : Load IDT descriptor into IDTR on given CPU
*  ARGUMENTS    : void
*  RETURNS      : void
*-------------------------------------------------------*/
void hw_idt_load(void);

/*-------------------------------------------------------*
*  FUNCTION     : hw_idt_setup()
*  PURPOSE      : Build and populate IDT tables, one per CPU
*  ARGUMENTS    : void
*  RETURNS      : void
*-------------------------------------------------------*/
void hw_idt_setup(void);

/*----------------------------------------------------*
*  FUNCTION     : idt_get_extra_stacks_required()
*  PURPOSE      : Returns the number of extra stacks required by ISRs
*  ARGUMENTS    : void
*  RETURNS      : number between 0..7
*  NOTES        : per CPU
*-------------------------------------------------------*/
UINT8 idt_get_extra_stacks_required(
    void
    );

#endif // _IDT_H_

