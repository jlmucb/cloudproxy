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

#ifndef _UVMM_LOCK_H_
#define _UVMM_LOCK_H_

#include "vmm_defs.h"
#include "hw_interlocked.h"
#include "vmm_dbg.h"


typedef struct _VMM_LOCK {
    volatile UINT32 uint32_lock;
    volatile CPU_ID owner_cpu_id;
    char padding[2];
} VMM_LOCK;

#define LOCK_INIT_STATE     {(UINT32) 0, (CPU_ID) -1, 0}

////////////////////////////////////////////////////////////////////////////////
//
// Read/Write lock
//
// multiple readers can read the data in parallel but an exclusive lock is
// needed while writing the data. When a writer is writing the data, readers
// will be blocked until the writer has finished writing
////////////////////////////////////////////////////////////////////////////////
typedef struct _VMM_READ_WRITE_LOCK {
    VMM_LOCK        lock;
    UINT32          padding;
    volatile INT32  readers;
} VMM_READ_WRITE_LOCK;


////////////////////////////////////////////////////////////////////////////////
//
// Various locking routines
//
////////////////////////////////////////////////////////////////////////////////
void
lock_acquire(    VMM_LOCK* lock );

void
interruptible_lock_acquire(    VMM_LOCK* lock );

void
lock_release(    VMM_LOCK* lock );

void
lock_initialize(  VMM_LOCK* lock );

#ifdef DEBUG
void
lock_print(    VMM_LOCK* lock );
#endif

void
lock_initialize_read_write_lock( VMM_READ_WRITE_LOCK * lock );

void
lock_acquire_readlock( VMM_READ_WRITE_LOCK * lock );

void
interruptible_lock_acquire_readlock( VMM_READ_WRITE_LOCK * lock );

void
lock_release_readlock( VMM_READ_WRITE_LOCK * lock );

void
lock_acquire_writelock( VMM_READ_WRITE_LOCK * lock );

void
interruptible_lock_acquire_writelock( VMM_READ_WRITE_LOCK * lock );

void
lock_release_writelock( VMM_READ_WRITE_LOCK * lock );


#endif // _UVMM_LOCK_H_


