#ifndef _KNOX_BYPASS_H_
#define _KNOX_BYPASS_H_

#define KMEM_ALLOC_SIZE   0x100000
#define MNT_LOCK_READONLY 0x400000

int32_t do_knox_bypass(uint64_t pTaskStruct, uint64_t pThreadInfo, char* pszRootExecPath);

#endif