#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# FNV-1a hash (replaces DJB2)
# credit: polymorphic build system

import sys

DEFAULT_SEED = 0x9590708C
FNV_PRIME    = 0x01000193

def hash_string( string, seed=DEFAULT_SEED ):
    """FNV-1a hash with uppercase (for Win32 API resolution)."""
    try:
        h = seed & 0xFFFFFFFF
        for x in string.upper():
            h ^= ord(x)
            h = (h * FNV_PRIME) & 0xFFFFFFFF
        return h
    except:
        pass

def hash_coffapi( string, seed=DEFAULT_SEED ):
    """FNV-1a hash case-sensitive (for COFF/BOF API resolution)."""
    try:
        h = seed & 0xFFFFFFFF
        for x in string:
            h ^= ord(x)
            h = (h * FNV_PRIME) & 0xFFFFFFFF
        return h
    except:
        pass

if __name__ in '__main__':
    try:
        seed = DEFAULT_SEED
        if len(sys.argv) >= 3:
            seed = int(sys.argv[2], 0)
        print('#define H_FUNC_%s 0x%x' % ( sys.argv[ 1 ].upper(), hash_string( sys.argv[ 1 ], seed ) ));
        print('#define H_COFFAPI_%s 0x%x' % ( sys.argv[ 1 ].upper(), hash_coffapi( sys.argv[ 1 ], seed ) ));
    except IndexError:
        print('usage: %s [string] [seed_hex]' % sys.argv[0]);
