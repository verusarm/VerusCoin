/*
 * This uses veriations of the clhash algorithm for Verus Coin, licensed
 * with the Apache-2.0 open source license.
 * 
 * Copyright (c) 2018 Michael Toutonghi
 * Distributed under the Apache 2.0 software license, available in the original form for clhash
 * here: https://github.com/lemire/clhash/commit/934da700a2a54d8202929a826e2763831bd43cf7#diff-9879d6db96fd29134fc802214163b95a
 * 
 * Original CLHash code and any portions herein, (C) 2017, 2018 Daniel Lemire and Owen Kaser
 * Faster 64-bit universal hashing
 * using carry-less multiplications, Journal of Cryptographic Engineering (to appear)
 *
 * Best used on recent x64 processors (Haswell or better).
 * 
 * This implements an intermediate step in the last part of a Verus block hash. The intent of this step
 * is to more effectively equalize FPGAs over GPUs and CPUs.
 *
 **/


#include "verus_hash.h"

#include <assert.h>
#include <string.h>
#include <x86intrin.h>

#ifdef __WIN32
#define posix_memalign(p, a, s) (((*(p)) = _aligned_malloc((s), (a))), *(p) ?0 :errno)
#endif

thread_local void *verusclhasher_random_data_;
thread_local int64_t verusclhasher_keySizeInBytes;
thread_local uint256 verusclhasher_seed;

// multiply the length and the some key, no modulo
static inline __m128i lazyLengthHash(uint64_t keylength, uint64_t length) {
    const __m128i lengthvector = _mm_set_epi64x(keylength,length);
    const __m128i clprod1 = _mm_clmulepi64_si128( lengthvector, lengthvector, 0x10);
    return clprod1;
}

// modulo reduction to 64-bit value. The high 64 bits contain garbage, see precompReduction64
static inline __m128i precompReduction64_si128( __m128i A) {

    //const __m128i C = _mm_set_epi64x(1U,(1U<<4)+(1U<<3)+(1U<<1)+(1U<<0)); // C is the irreducible poly. (64,4,3,1,0)
    const __m128i C = _mm_cvtsi64_si128((1U<<4)+(1U<<3)+(1U<<1)+(1U<<0));
    __m128i Q2 = _mm_clmulepi64_si128( A, C, 0x01);
    __m128i Q3 = _mm_shuffle_epi8(_mm_setr_epi8(0, 27, 54, 45, 108, 119, 90, 65, (char)216, (char)195, (char)238, (char)245, (char)180, (char)175, (char)130, (char)153),
                                  _mm_srli_si128(Q2,8));
    __m128i Q4 = _mm_xor_si128(Q2,A);
    const __m128i final = _mm_xor_si128(Q3,Q4);
    return final;/// WARNING: HIGH 64 BITS CONTAIN GARBAGE
}

static inline uint64_t precompReduction64( __m128i A) {
    return _mm_cvtsi128_si64(precompReduction64_si128(A));
}

// verus intermediate hash extra
static __m128i __verusclmulwithoutreduction64alignedrepeat(const __m128i *randomsource, const __m128i buf[4], uint64_t keyMask)
{
    __m128i acc = _mm_setzero_si128();

    __m128i const *pbuf = buf;

    // divide key mask by 32 from bytes to __m128i
    keyMask >>= 5;

    for (int64_t i = 0; i < 32; i++)
    {
        const uint64_t selector = _mm_cvtsi128_si64(acc);

        // add 0 - 31, depending on keyoffset, low and high 128 bit random components are swapped this pass
        int randOffset = ((selector >> 6) & keyMask);
        const int64_t keyoffset = randOffset ? (selector >> 4 & 0x02) - 1 : 1;
        __m128i const *prand = randomsource + randOffset;

        // select random start and order of pbuf processing
        pbuf = buf + (selector & 3);

        // 1 additional bit tested below, so 5 bits used in selector to statistically weight
        // two heavier paths at 0.125 each
        switch (selector & 0x1c)
        {
            case 0:
            {
                const __m128i temp1 = _mm_load_si128(prand+keyoffset);
                const __m128i temp2 = _mm_load_si128((selector & 1) ? pbuf-1 : pbuf+1);
                const __m128i add1 = _mm_xor_si128(temp1, temp2);
                const __m128i clprod1 = _mm_clmulepi64_si128(add1, add1, 0x10);
                acc = _mm_xor_si128(clprod1, acc);
                const __m128i temp12 = _mm_load_si128(prand);
                const __m128i temp22 = _mm_load_si128(pbuf);
                const __m128i add12 = _mm_xor_si128(temp12, temp22);
                const __m128i clprod12 = _mm_clmulepi64_si128(add12, add12, 0x10);
                acc = _mm_xor_si128(clprod12, acc);
                break;
            }
            case 4:
            {
                const __m128i temp1 = _mm_load_si128(prand);
                const __m128i temp2 = _mm_load_si128(pbuf);
                const __m128i add1 = _mm_xor_si128(temp1, temp2);
                const __m128i clprod1 = _mm_clmulepi64_si128(add1, add1, 0x10);
                acc = _mm_xor_si128(clprod1, acc);
                const __m128i clprod2 = _mm_clmulepi64_si128(temp2, temp2, 0x10);
                acc = _mm_xor_si128(clprod2, acc);
                const __m128i temp12 = _mm_load_si128(prand+keyoffset);
                const __m128i temp22 = _mm_load_si128((selector & 1) ? pbuf-1 : pbuf+1);
                const __m128i add12 = _mm_xor_si128(temp12, temp22);
                acc = _mm_xor_si128(add12, acc);
                break;
            }
            case 8:
            {
                const __m128i temp1 = _mm_load_si128(prand+keyoffset);
                const __m128i temp2 = _mm_load_si128(pbuf);
                const __m128i add1 = _mm_xor_si128(temp1, temp2);
                acc = _mm_xor_si128(add1, acc);
                const __m128i temp12 = _mm_load_si128(prand);
                const __m128i temp22 = _mm_load_si128((selector & 1) ? pbuf-1 : pbuf+1);
                const __m128i add12 = _mm_xor_si128(temp12, temp22);
                const __m128i clprod12 = _mm_clmulepi64_si128(add12, add12, 0x10);
                acc = _mm_xor_si128(clprod12, acc);
                const __m128i clprod22 = _mm_clmulepi64_si128(temp22, temp22, 0x10);
                acc = _mm_xor_si128(clprod22, acc);
                break;
            }
            case 0x0c:
            {
                const __m128i temp1 = _mm_load_si128(prand);
                const __m128i temp2 = _mm_load_si128((selector & 1) ? pbuf-1 : pbuf+1);
                const __m128i add1 = _mm_xor_si128(temp1, temp2);

                // cannot be zero here
                const int32_t divisor = _mm_cvtsi128_si32(acc);

                acc = _mm_xor_si128(add1, acc);

                const int64_t dividend = _mm_cvtsi128_si64(acc);
                const __m128i modulo = _mm_cvtsi32_si128(dividend % divisor);
                acc = _mm_xor_si128(modulo, acc);

                if (dividend & 1)
                {
                    const __m128i temp12 = _mm_load_si128(prand+keyoffset);
                    const __m128i temp22 = _mm_load_si128(pbuf);
                    const __m128i add12 = _mm_xor_si128(temp12, temp22);
                    const __m128i clprod12 = _mm_clmulepi64_si128(add12, add12, 0x10);
                    acc = _mm_xor_si128(clprod12, acc);
                    const __m128i clprod22 = _mm_clmulepi64_si128(temp22, temp22, 0x10);
                    acc = _mm_xor_si128(clprod22, acc);
                }
                break;
            }
            case 0x10:
            {
                // a few AES operations, basically a mini-keyed Haraka256 with only 3 rounds
                const __m128i *rc = (prand - randomsource) < 12 ? randomsource : prand, *buftmp = (selector & 1) ? pbuf-1 : pbuf+1;
                __m128i tmp;

                __m128i temp1 = _mm_load_si128(buftmp);
                __m128i temp2 = _mm_load_si128(pbuf);

                AES2(temp1, temp2, 0);
                MIX2(temp1, temp2);

                AES2(temp1, temp2, 4);
                MIX2(temp1, temp2);

                AES2(temp1, temp2, 8);
                MIX2(temp1, temp2);

                temp1 = _mm_xor_si128(temp1, _mm_load_si128(buftmp));
                temp2 = _mm_xor_si128(temp2, _mm_load_si128(pbuf));

                acc = _mm_xor_si128(temp1, acc);
                acc = _mm_xor_si128(temp2, acc);
                break;
            }
            case 0x14:
            {
                // we'll just call this one the monkins loop, inspired by Chris
                const __m128i *rc = (prand - randomsource) < 32 ? randomsource : prand, *buftmp = (selector & 1) ? pbuf-1 : pbuf+1;
                __m128i tmp;


                uint64_t rounds = selector >> 61; // loop randomly between 1 and 8 times
                uint64_t aesround = 0;

                do
                {
                    if (selector & (0x10000000 << rounds))
                    {
                        const __m128i temp1 = _mm_load_si128(prand++);
                        const __m128i temp2 = _mm_load_si128(rounds & 1 ? pbuf : buftmp);
                        const __m128i add1 = _mm_xor_si128(temp1, temp2);
                        const __m128i clprod1 = _mm_clmulepi64_si128(add1, add1, 0x10);
                        acc = _mm_xor_si128(clprod1, acc);
                    }
                    else
                    {
                        __m128i temp1 = _mm_load_si128(prand++);
                        __m128i temp2 = _mm_load_si128(rounds & 1 ? buftmp : pbuf);
                        AES2(temp1, temp2, aesround++ << 2);
                        MIX2(temp1, temp2);
                        acc = _mm_xor_si128(temp1, acc);
                        acc = _mm_xor_si128(temp2, acc);
                    }
                } while (rounds--);
                break;
            }
            case 0x18:
            {
                const __m128i temp1 = _mm_load_si128((selector & 1) ? pbuf-1 : pbuf+1);
                const __m128i temp2 = _mm_load_si128(prand);
                const __m128i add1 = _mm_xor_si128(temp1, temp2);
                const __m128i clprod1 = _mm_clmulepi64_si128(add1, add1, 0x10);
                acc = _mm_xor_si128(clprod1, acc);
                break;
            }
            case 0x1c:
            {
                const __m128i temp1 = _mm_load_si128(pbuf);
                const __m128i temp2 = _mm_load_si128(prand + keyoffset);
                const __m128i add1 = _mm_xor_si128(temp1, temp2);
                const __m128i clprod1 = _mm_clmulepi64_si128(add1, add1, 0x10);
                acc = _mm_xor_si128(clprod1, acc);
                const __m128i temp3 = _mm_load_si128(prand);
                acc = _mm_xor_si128(temp3, acc);
                break;
            }
        }
    }
    return acc;
}

// hashes 64 bytes only by doing a carryless multiplication and reduction of the repeated 64 byte sequence 16 times, 
// returning a 64 bit hash value
uint64_t verusclhash(const void * random, const unsigned char buf[64], uint64_t keyMask) {
    const unsigned int  m = 128;// we process the data in chunks of 16 cache lines
    const __m128i * rs64 = (__m128i *)random;
    const __m128i * string = (const __m128i *) buf;

    __m128i  acc = __verusclmulwithoutreduction64alignedrepeat(rs64, string, keyMask);
    acc = _mm_xor_si128(acc, lazyLengthHash(1024, 64));
    return precompReduction64(acc);
}

void *alloc_aligned_buffer(uint64_t bufSize)
{
    void *answer = NULL;
    if (posix_memalign(&answer, sizeof(__m128i), bufSize))
    {
        return NULL;
    }
    else
    {
        return answer;
    }
}
