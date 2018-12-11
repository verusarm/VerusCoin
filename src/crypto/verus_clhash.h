/*
 * This uses veriations of the clhash algorithm for Verus Coin, licensed
 * with the Apache-2.0 open source license.
 * 
 * Copyright (c) 2018 Michael Toutonghi
 * Distributed under the Apache 2.0 software license, available in the original form for clhash
 * here: https://github.com/lemire/clhash/commit/934da700a2a54d8202929a826e2763831bd43cf7#diff-9879d6db96fd29134fc802214163b95a
 * 
 * CLHash is a very fast hashing function that uses the
 * carry-less multiplication and SSE instructions.
 *
 * Original CLHash code (C) 2017, 2018 Daniel Lemire and Owen Kaser
 * Faster 64-bit universal hashing
 * using carry-less multiplications, Journal of Cryptographic Engineering (to appear)
 *
 * Best used on recent x64 processors (Haswell or better).
 *
 **/

#ifndef INCLUDE_VERUS_CLHASH_H
#define INCLUDE_VERUS_CLHASH_H

#include "clhash.h"

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    // Verus Key size must include an extra 128 bytes from what is divisible by 8
    VERUSKEYSIZE=1024 * 16 + 256
};

extern thread_local void *verusclhasher_random_data_;
extern thread_local int64_t verusclhasher_keySizeInBytes;

uint64_t verusclhash(const void * random, const unsigned char buf[64], uint64_t keyMask);

void *alloc_aligned_buffer(uint64_t bufSize);

#ifdef __cplusplus
} // extern "C"
#endif

#ifdef __cplusplus

#include <vector>
#include <string>

// special high speed hasher for VerusHash 2.0
struct verusclhasher {
    int64_t keySizeIn64BitWords;
    int64_t keyMask;

    verusclhasher(uint64_t keysize=VERUSKEYSIZE) : keySizeIn64BitWords((keysize >> 7) << 4)
    {
        int64_t newKeySize = (keysize >> 7) << 7;
        if (verusclhasher_random_data_ && newKeySize != verusclhasher_keySizeInBytes)
        {
            std::free((void *)verusclhasher_random_data_);
            verusclhasher_random_data_ = NULL;
            verusclhasher_keySizeInBytes = 0;
        }
        if (!verusclhasher_random_data_)
        {
            if (verusclhasher_random_data_ = alloc_aligned_buffer(newKeySize))
            {
                verusclhasher_keySizeInBytes = newKeySize;

                int i = 0;
                while (keysize >>= 1)
                {
                    i++;
                }
                keyMask = (((uint64_t)1) << i) - 1;
            }
            else
            {
                keyMask = 0;
            }
        }
    }

    uint64_t operator()(const unsigned char buf[64]) const {
        return verusclhash(verusclhasher_random_data_, buf, keyMask);
    }
};

#endif // #ifdef __cplusplus

#endif // INCLUDE_VERUS_CLHASH_H
