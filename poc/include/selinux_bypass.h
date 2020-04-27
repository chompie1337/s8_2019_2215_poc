#ifndef _SELINUX_BYPASS_H_
#define _SELINUX_BYPASS_H_

// Decision value that indicates "all permissions" for an avc_cache slot 
#define AVC_DECISION_ALLOWALL 0xffffffff

// Value to suppress output from libsepol
#define SEPOL_NOT_VERBOSE     0

// Maximum length for a SELinux context string
#define MAX_SELINUX_CXT_LEN   0x200

int32_t do_selinux_bypass(char* pszSepolicyPath);

#endif