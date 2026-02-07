#pragma once

#include <Demon.h>
#include <generated/ObfStrings.h>

VOID StrDecrypt( PVOID Dst, CONST BYTE* Enc, CONST BYTE* Key, SIZE_T Len );

#define OBFSTR_DECRYPT(id, buf) \
    StrDecrypt( (buf), OBFSTR_##id##_ENC, OBFSTR_##id##_KEY, OBFSTR_##id##_LEN )

