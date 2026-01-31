# Task: P1 — Polymorphic Build System + Static Signature Evasion

## Context
This is the Havoc C2 framework. The Demon implant (in `payloads/Demon/`) is detected by Elastic YARA rules and CrowdStrike behavioral analysis due to static byte patterns and the well-known DJB2 hash with seed 5381.

We need to make the build **polymorphic** — each compilation produces unique constants that break static signatures.

## What to Do

### Part 1: Create Polymorphic Build Script

Create `payloads/Demon/scripts/polymorphic_build.py` that:

1. **Generates a random hash seed** (32-bit, non-zero, not 5381)
2. **Generates a random magic value** (32-bit, not 0xDEADBEEF)
3. **Generates a random stack padding value** (multiple of 8, between 0x10 and 0x100)
4. **Computes ALL API hash constants** using FNV-1a algorithm with the random seed
5. **Outputs a generated header** at `payloads/Demon/include/generated/build_constants.h`

The script must:
- Accept `--seed <value>` to set a fixed seed (for reproducibility/debugging)
- Accept `--magic <value>` to set a fixed magic value
- By default, generate random values
- Print what it generated to stdout for logging

**Hash constants to generate** (extract all `H_FUNC_*`, `H_MODULE_*`, and `H_COFFAPI_*` names from `payloads/Demon/include/common/Defines.h`):

The script needs to know the **actual Windows API names** that each hash constant maps to. Here's the mapping pattern:
- `H_FUNC_NTALLOCATEVIRTUALMEMORY` → hashes the string `"NtAllocateVirtualMemory"` (uppercased)
- `H_MODULE_NTDLL` → hashes the string `"NTDLL.DLL"` (uppercased)
- `H_FUNC_LOADLIBRARYW` → hashes `"LoadLibraryW"` (uppercased)

The script should also generate constants needed by the KaynLdr shellcode (`payloads/Shellcode/`):
- `NTDLL_HASH` → hash of `"ntdll.dll"` (uppercased to `"NTDLL.DLL"`)
- `SYS_LDRLOADDLL` → hash of `"LdrLoadDll"` (uppercased)
- `SYS_NTALLOCATEVIRTUALMEMORY` → hash of `"NtAllocateVirtualMemory"` (uppercased)
- `SYS_NTPROTECTEDVIRTUALMEMORY` → hash of `"NtProtectVirtualMemory"` (uppercased)

### Part 2: Replace DJB2 Hash Algorithm with FNV-1a

**FNV-1a algorithm** (with configurable seed as the offset basis):
```c
ULONG HashFnv1a(PVOID String, ULONG Length, BOOL Upper) {
    ULONG Hash = HASH_SEED;  // from generated header, replaces 5381
    PUCHAR Ptr = String;
    if (!String) return 0;
    do {
        UCHAR character = *Ptr;
        if (!Length) {
            if (!*Ptr) break;
        } else {
            if ((ULONG)(C_PTR(Ptr) - String) >= Length) break;
            if (!*Ptr) { ++Ptr; continue; }
        }
        if (Upper) {
            if (character >= 'a') character -= 0x20;
        }
        Hash ^= character;
        Hash *= 0x01000193;  // FNV-1a 32-bit prime
        ++Ptr;
    } while (TRUE);
    return Hash;
}
```

Files to modify:

1. **`payloads/Demon/include/core/Win32.h`**:
   - Change `#define HASH_KEY 5381` to `#include "generated/build_constants.h"` and use `HASH_SEED` from there
   - Or replace inline: `#define HASH_KEY HASH_SEED`

2. **`payloads/Demon/src/core/Win32.c`** — `HashEx()` function:
   - Replace DJB2: `Hash = ((Hash << 5) + Hash) + character`
   - With FNV-1a: `Hash ^= character; Hash *= 0x01000193;`
   - Keep the same function signature and null/length handling

3. **`payloads/Shellcode/Source/Utils.c`** — `HashString()` function:
   - Same change: replace DJB2 with FNV-1a
   - The seed must match (hardcoded from the generated value, or use a shared define)
   - IMPORTANT: This runs in the shellcode loader, so it must use the SAME seed as the constants in Core.h

4. **`payloads/Shellcode/Scripts/Hasher.c`**:
   - Update the `Hash()` function to use FNV-1a with configurable seed
   - Accept seed as argv[2] (optional, default to a known value)

5. **`payloads/Demon/scripts/hash_func.py`**:
   - Update to use FNV-1a algorithm
   - Accept `--seed` parameter
   - Must produce identical output to the C implementations

### Part 3: Replace Static Hash Constants

1. **`payloads/Demon/include/common/Defines.h`**:
   - Remove all hardcoded `H_FUNC_*` and `H_MODULE_*` hex values
   - Instead, `#include "generated/build_constants.h"`
   - Keep all the other defines (PROCESS_ARCH, WIN_VERSION, etc.)
   - Keep `DEMON_MAGIC_VALUE` but change it to use the generated value: `#define DEMON_MAGIC_VALUE BUILD_MAGIC_VALUE`

2. **`payloads/Shellcode/Include/Core.h`**:
   - Replace hardcoded `NTDLL_HASH`, `SYS_*` values with includes from generated header
   - Or create a separate generated header for the shellcode

### Part 4: Magic Value + Stack Padding

1. **`payloads/Demon/include/common/Defines.h`**:
   - `#define DEMON_MAGIC_VALUE BUILD_MAGIC_VALUE` (from generated header)

2. **`payloads/Demon/src/Demon.c`** — `DemonConfig()` function:
   - Add stack padding: insert `volatile BYTE _pad[BUILD_STACK_PAD]` at the start of the function
   - This changes the stack frame size, breaking YARA rule `Windows_Trojan_Havoc_88053562`

3. **`teamserver/pkg/agent/commands.go`**:
   - Change `DEMON_MAGIC_VALUE = 0xDEADBEEF` to a configurable value
   - Add a comment explaining it must match the build

4. **`teamserver/pkg/handlers/handlers.go`**, **`teamserver/pkg/db/agents.go`**, **`teamserver/pkg/agent/demons.go`**, **`teamserver/cmd/server/dispatch.go`**:
   - All references to `DEMON_MAGIC_VALUE` should use the constant from `commands.go`
   - These probably already do — just verify

### Part 5: Generated Header Format

`payloads/Demon/include/generated/build_constants.h` should look like:
```c
/* AUTO-GENERATED by polymorphic_build.py — DO NOT EDIT */
#ifndef BUILD_CONSTANTS_H
#define BUILD_CONSTANTS_H

/* Build-time polymorphic seed */
#define HASH_SEED 0xABCD1234

/* Build-time magic value */
#define BUILD_MAGIC_VALUE 0x12345678

/* Build-time stack padding */
#define BUILD_STACK_PAD 0x48

/* Module hashes (FNV-1a with seed HASH_SEED) */
#define H_MODULE_NTDLL       0x...
#define H_MODULE_KERNEL32    0x...
/* ... all module hashes ... */

/* Function hashes */
#define H_FUNC_NTALLOCATEVIRTUALMEMORY  0x...
/* ... all function hashes ... */

/* KaynLdr shellcode hashes */
#define NTDLL_HASH                    0x...
#define SYS_LDRLOADDLL                0x...
#define SYS_NTALLOCATEVIRTUALMEMORY   0x...
#define SYS_NTPROTECTEDVIRTUALMEMORY  0x...

#endif /* BUILD_CONSTANTS_H */
```

## Critical Constraints

1. **DO NOT change function signatures** — the rest of the codebase calls these functions
2. **The hash algorithm must be IDENTICAL** in Demon (`HashEx`), KaynLdr (`HashString`), Python (`hash_func.py`), and the build script
3. **Hash values must match** — if the build script generates `H_FUNC_NTALLOCATEVIRTUALMEMORY = 0xABC`, the runtime `HashEx("NtAllocateVirtualMemory")` must return `0xABC`
4. **Preserve null/length handling** in hash functions exactly as-is — only change the core hash computation
5. **Create the `generated/` directory** and add a `.gitignore` that ignores `build_constants.h` (since it's generated per-build)
6. **Add a default `build_constants.h`** with a known seed for development/testing (so the project still compiles without running the script)

## Files to Read First
- `payloads/Demon/include/common/Defines.h` — all existing hash constants
- `payloads/Demon/src/core/Win32.c` — HashEx() function and LdrFunctionAddr/LdrModulePeb
- `payloads/Shellcode/Source/Utils.c` — HashString() function
- `payloads/Shellcode/Include/Core.h` — shellcode hash constants
- `payloads/Demon/scripts/hash_func.py` — existing hash script
- `payloads/Demon/src/Demon.c` — DemonConfig() function
- `payloads/Demon/src/core/Package.c` line 179 — DEMON_MAGIC_VALUE usage
- `teamserver/pkg/agent/commands.go` — server-side magic value

## Testing
After changes, verify by:
1. Run `python3 payloads/Demon/scripts/polymorphic_build.py` and check the output header
2. Run `python3 payloads/Demon/scripts/polymorphic_build.py --seed 5381` and verify backward compatibility (optional)
3. Ensure the generated header has all required constants
4. Run `python3 payloads/Demon/scripts/hash_func.py NtAllocateVirtualMemory` and compare against the generated header
