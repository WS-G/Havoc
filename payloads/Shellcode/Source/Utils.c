#include <Utils.h>
#include <Macro.h>

#define FNV_PRIME 0x01000193

SEC( text, B ) UINT_PTR HashString( LPVOID String, UINT_PTR Length )
{
    ULONG	Hash = HASH_KEY;
    PUCHAR	Ptr  = String;

    do
    {
        UCHAR character = *Ptr;

        if ( ! Length )
        {
            if ( !*Ptr ) break;
        }
        else
        {
            if ( (ULONG) ( Ptr - (PUCHAR)String ) >= Length ) break;
            if ( !*Ptr ) ++Ptr;
        }

        if ( character >= 'a' )
            character -= 0x20;

        Hash ^= character;
        Hash *= FNV_PRIME;
        ++Ptr;
    } while ( TRUE );

    return Hash;
}