#ifndef _KALLSYMS__H_
#define _KALLSYMS__H_

// Maximum number of memory bytes to search for the kallsyms table 
#define KALLSYMS_MAX_SEARCH 0x2000000

// Number of increasing entries needed to find the start of the kallsyms table
#define KALLSYMS_INC_COUNT 0x9C40

// Maximum number of indices in the kallsyms token table
#define KALLSYMS_NUM_TOKENS 0x100

// Maximum number of characters to read in a kernel symbol name
#define KALLSYMS_MAX_NAME_LEN 0x80

typedef struct kallsyms_table {
    uint64_t pAddrs;
    uint64_t pNames;
    uint64_t pMarkers;
    uint64_t pTokenTbl;
    uint64_t ulNumSyms;
    char*    pszTokenTblData;
    uint16_t usTokenIndexData[KALLSYMS_NUM_TOKENS];
} kallsyms_table;

uint64_t get_kernel_sym_addr(char* pszSymName);
void cleanup_kallsyms_tbl(void);

#endif