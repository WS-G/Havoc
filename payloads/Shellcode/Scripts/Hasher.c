#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

/*
 * FNV-1a hash (replaces DJB2)
 * Seed should match HASH_KEY in Core.h / Win32.h
 */
#define DEFAULT_SEED 0x9590708C
#define FNV_PRIME    0x01000193

unsigned long Hash( char* String, unsigned long Seed )
{
    unsigned long Hash = Seed;
    while ( *String )
    {
        unsigned char c = (unsigned char)*String++;
        Hash ^= c;
        Hash *= FNV_PRIME;
    }
    return Hash;
}

void ToUpperString(char * temp) {
    char *s = temp;
    while (*s) {
        *s = toupper((unsigned char) *s);
        s++;
    }
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        printf("Usage: %s <string> [seed_hex]\n", argv[0]);
        return 0;
    }

    unsigned long seed = DEFAULT_SEED;
    if (argc >= 3) {
        seed = strtoul(argv[2], NULL, 16);
    }

    ToUpperString(argv[1]);
    printf("\n[+] FNV-1a (seed=0x%lx) Hashed %s ==> 0x%lx\n\n", seed, argv[1], Hash(argv[1], seed));
    return 0;
}
