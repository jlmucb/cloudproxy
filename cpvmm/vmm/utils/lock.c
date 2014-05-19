/*
 * Copyright (c) 2013 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "libc.h"
#include "hw_includes.h"
#include "lock.h"
#include "ipc.h"
#include "vmm_dbg.h"
#include "file_codes.h"

#define VMM_DEADLOOP()                 VMM_DEADLOOP_LOG(LOCK_C)
#define VMM_ASSERT(__condition)        VMM_ASSERT_LOG(LOCK_C, __condition)
#define VMM_ASSERT_NOLOCK(__condition) VMM_ASSERT_NOLOCK_LOG(LOCK_C, __condition)

// lock_try_acquire - returns TRUE if lock was acquired and FALSE if not
BOOLEAN lock_try_acquire( VMM_LOCK* lock );


void lock_acquire( VMM_LOCK* lock )
{
#if 0
    CPU_ID this_cpu_id = hw_cpu_id();

    if (! lock) {
        // error
        return;
    }
    while (FALSE == lock_try_acquire(lock)) {
        VMM_ASSERT_NOLOCK(lock->owner_cpu_id != this_cpu_id);
        hw_pause();
    }
    lock->owner_cpu_id = this_cpu_id;
#endif
}

void interruptible_lock_acquire( VMM_LOCK* lock )
{
#if 0
    CPU_ID this_cpu_id = hw_cpu_id();
    BOOLEAN ipc_processed = FALSE;

    if (! lock) {
        // error
        return;
    }

    while (FALSE == lock_try_acquire(lock)) {
        VMM_ASSERT_NOLOCK(lock->owner_cpu_id != this_cpu_id);
        ipc_processed = ipc_process_one_ipc();

        if(FALSE == ipc_processed) {
            hw_pause();
        }
    }

    lock->owner_cpu_id = this_cpu_id;
#endif
}

void lock_release( VMM_LOCK* lock )
{
#if 0
    if (! lock) {
        // error
        return;
    }

    lock->owner_cpu_id = (CPU_ID)-1;
    hw_interlocked_assign ((INT32 volatile *)(&(lock->uint32_lock)), 0);
#endif
}

BOOLEAN lock_try_acquire( VMM_LOCK* lock )
{
#if 0
    UINT32 expected_value = 0, current_value;
    UINT32 new_value = 1;

    if (! lock) {
        // error
        return FALSE;
    }

    current_value =
            hw_interlocked_compare_exchange((INT32 volatile *)(&(lock->uint32_lock)),
                                              expected_value, new_value );
    return (current_value == expected_value);
#endif
    return TRUE;
}


void lock_initialize(  VMM_LOCK* lock )
{
#if 0
    lock_release( lock );
#endif
}

void lock_initialize_read_write_lock( VMM_READ_WRITE_LOCK * lock )
{
#if 0
    lock_initialize(&lock->lock);
    lock->readers = 0;
#endif
}


void lock_acquire_readlock( VMM_READ_WRITE_LOCK * lock )
{
#if 0
    lock_acquire(&lock->lock);
    hw_interlocked_increment((INT32*)(&lock->readers));
    VMM_ASSERT( lock->readers );
    lock_release(&lock->lock);
#endif
}

void interruptible_lock_acquire_readlock( VMM_READ_WRITE_LOCK * lock )
{
#if 0
    interruptible_lock_acquire(&lock->lock);
    hw_interlocked_increment((INT32*)(&lock->readers));
    VMM_ASSERT( lock->readers );
    lock_release(&lock->lock);
#endif
}

void lock_release_readlock( VMM_READ_WRITE_LOCK * lock )
{
#if 0
    VMM_ASSERT( lock->readers );
    hw_interlocked_decrement((INT32*)(&lock->readers));
#endif
}


void lock_acquire_writelock( VMM_READ_WRITE_LOCK * lock )
{
#if 0
    lock_acquire(&lock->lock);
    while(lock->readers) {
        hw_pause();
         // wait until readers == 0
    }
    VMM_ASSERT( lock->readers == 0 );
#endif
}


void interruptible_lock_acquire_writelock( VMM_READ_WRITE_LOCK * lock )
{
#if 0
    BOOLEAN ipc_processed = FALSE;

    interruptible_lock_acquire(&lock->lock);
    while(lock->readers) {
        ipc_processed = ipc_process_one_ipc();

        if(FALSE == ipc_processed) {
            hw_pause();
        }
        //  wait until readers == 0
    }
    VMM_ASSERT( lock->readers == 0 );
#endif
}


void lock_release_writelock( VMM_READ_WRITE_LOCK * lock )
{
#if 0
    VMM_ASSERT( lock->readers == 0 );
    lock_release(&lock->lock);
#endif
}


VMM_DEBUG_CODE(

void lock_print( VMM_LOCK* lock )
{
#if 0
    VMM_LOG(mask_anonymous, level_trace,"lock %p: value=%d, owner=%d\r\n", lock, lock->uint32_lock, lock->owner_cpu_id);
#endif
}

)


