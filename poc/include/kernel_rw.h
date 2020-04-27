#ifndef _KERNEL_RW__H_
#define _KERNEL_RW__H_

int32_t check_kernel_memory_valid(uint64_t pAddr, uint64_t ulSz);

uint8_t kernel_read_uchar(uint64_t pAddr);
uint32_t kernel_read_uint(uint64_t pAddr);
uint64_t kernel_read_ulong(uint64_t pAddr);
int32_t kernel_read(uint64_t pAddr, void* pRecvBuff, uint64_t ulSz);

int32_t kernel_write_uint(uint64_t pAddr, uint32_t uiValue);
int32_t kernel_write_ulong(uint64_t pAddr, uint64_t ulValue);
int32_t kernel_write(uint64_t pAddr, void* pDataBuff, uint64_t ulSz);

#endif