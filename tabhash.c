/*
 * Copyright 2023 Regents of Nanjing University of Aeronautics and Astronautics and 
 * Hohai University, Miao Cai <miaocai@nuaa.edu.cn> and Junru Shen <jrshen@hhu.edu.cn>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free 
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "tabhash.h"



#define TAB_SCALAR 0 /* Portable scalar version */
#define TAB_SSE2   1 /* SSE2 for Pentium 4 and all x86_64 */
#define TAB_AVX2   2 /* AVX2 for Haswell and Bulldozer */
#define TAB_NEON   3 /* NEON for most ARMv7-A and all AArch64 */
#if defined(__GNUC__)
#  if defined(__AVX2__)
#    include <immintrin.h>
#    define TAB_VECTOR TAB_AVX2
#  elif defined(__SSE2__)
//#    include <emmintrin.h>
//#    define TAB_VECTOR TAB_SSE2
#    define TAB_VECTOR TAB_SCALAR
#  elif defined(__ARM_NEON__) || defined(__ARM_NEON)
//#    include <arm_neon.h>
//#    define TAB_VECTOR TABB_NEON
#    define TAB_VECTOR TAB_SCALAR
#  endif
#endif
#ifndef TAB_VECTOR
#  define TAB_VECTOR TAB_SCALAR
#endif

typedef __uint128_t uint128_t;

////////////////////////////////////////////////////////////////////////////////
// Utility functions
////////////////////////////////////////////////////////////////////////////////

static inline uint8_t  TAB_take_1(const uint8_t **p){ uint8_t  v; v = **p; *p += 1; return v; }
static inline uint16_t TAB_take_2(const uint8_t **p){ uint16_t v; memcpy(&v, *p, 2); *p += 2; return v; }
static inline uint32_t TAB_take_4(const uint8_t **p){ uint32_t v; memcpy(&v, *p, 4); *p += 4; return v; }
static inline uint64_t TAB_take_8(const uint8_t **p){ uint64_t v; memcpy(&v, *p, 8); *p += 8; return v; }
static inline uint64_t TAB_take_n(const uint8_t **data, int n){
   uint64_t v = 0;
   if (n & 4) v = TAB_take_4(data);
   if (n & 2) v = (v << 16) | TAB_take_2(data);
   if (n & 1) v = (v << 8) | TAB_take_1(data);
   return v;
}

static uint128_t TAB_combine127(uint128_t acc, uint128_t h, uint128_t a) {
   // Compute acc * a + h  lazy mod 2^127-1
   uint64_t x[2], y[2];
   memcpy(&x, &a, sizeof(x));
   memcpy(&y, &acc, sizeof(y));
   // I don't actually know if I've flipped the high and low bits here
   uint128_t y0x0 = (uint128_t)y[0]*x[0];
   uint128_t y0x1 = (uint128_t)y[0]*x[1];
   uint128_t y1x0 = (uint128_t)y[1]*x[0];
   uint128_t y1x1 = (uint128_t)y[1]*x[1];
   // Compute (y[0]*2^64 + y[1])(x[0]*2^64 + x[1])
   //       = y[0]x[0]*2^128 + (y[0]x[1] + y[1]x[0])*2^64 + y[1]x[1]
   // Shifted down 127: (Separate shifts to avoid overflow problems.)
   // Note that we actually assume (h >> 127) is 0.
   uint128_t hi = (y0x0 << 1) + (y0x1 >> 63) + (y1x0 >> 63) + (y1x1 >> 127) + (h >> 127);
   // And the low 127 bits: (Overflows are less of an issue here.)
   uint128_t lo = (((y0x1 + y1x0) << 64) + y1x1 + h) % ((uint128_t)1<<127);
   return hi + lo;
}

static uint64_t TAB_combine61(uint64_t acc, uint64_t h, uint64_t a) {
   uint128_t val = (uint128_t)acc * a + h;
   return (val % (1ull << 61)) + (val >> 61);
}

////////////////////////////////////////////////////////////////////////////////
// Generator Implementation
////////////////////////////////////////////////////////////////////////////////

void TAB_init_generator(TAB_generator* gen, uint64_t seed[TAB_SEED_LENGTH]) {
   for (int i = 0; i < TAB_SEED_LENGTH; i++)
      gen->seed[i] = seed[i];
}

uint64_t TAB_generate(TAB_generator* gen, uint64_t x) {
   // x < 2^126 suffices.
   const uint128_t P = (((uint128_t)1) << 127) - 1;
   uint128_t res = gen->seed[0];
   for (int i = 1; i < TAB_SEED_LENGTH/2; i+=2) {
      uint128_t a = ((uint128_t)gen->seed[i] << 64 | gen->seed[i+1]) % P;
      res = TAB_combine127(res, a, x);
   }
   if (res >= P)
      res -= P;
   return (uint64_t)res;
}

uint128_t rand128(TAB_generator* gen, uint64_t x) {
   uint128_t hi = (uint128_t)TAB_generate(gen, x);
   uint128_t lo = (uint128_t)TAB_generate(gen, x+1);
   return hi << 64 | lo;
}


void TAB_init_hash(TAB_hash* sec, TAB_generator* gen, uint64_t seed) {
   // TODO: Use FFT to generate values more efficiently
   uint64_t x = seed;
   for (int i = 0; i < TAB_BLOCK_LENGTH; i++) {
      sec->nh_table[i] = TAB_generate(gen, x++);
      sec->ms_table[i] = rand128(gen, x+=2);
   }

   for (int i = 0; i < 8; i++)
      for (int j = 0; j < 256; j++)
         sec->tab_table[i][j] = TAB_generate(gen, x++);

   // This is not completely uniform in [p], but that only changes our
   // collision rate by a tiny amount.
   sec->alpha = TAB_generate(gen, x++) % ((1ull << 61)-1);

   sec->ms_extra = rand128(gen, x+=2);
}

void TAB_init_hash_64(TAB_hash_64* sec, TAB_generator* gen, uint64_t seed) {
   uint64_t x = seed;
   for (int i = 0; i < TAB_BLOCK_LENGTH; i++) {
      sec->nh_table[i] = TAB_generate(gen, x++);
      sec->ms_table[i] = rand128(gen, x+=2);
   }
   for (int i = 0; i < 8; i++)
      for (int j = 0; j < 256; j++)
         sec->tab_table[i][j] = TAB_generate(gen, x++);
   sec->alpha = rand128(gen, x+=2) % ((uint128_t)1 << 127) - 1;
   sec->ms_extra = rand128(gen, x+=2);
}

////////////////////////////////////////////////////////////////////////////////
// Block hashes
////////////////////////////////////////////////////////////////////////////////

#if TAB_VECTOR == TAB_AVX2
static uint64_t TAB_BLOCK_vector_nh32(const uint64_t* random, const uint8_t* data) {
   __m256i acc = _mm256_set_epi64x(0, 0, 0, 0);

   const  __m256i* const input  = (const __m256i *)data;
   const  __m256i* const _random = (const __m256i *)random;

   // We eat 256 bits (4 words) for each iteration
   for (size_t i = 0; i < TAB_BLOCK_LENGTH/4;) {
      __builtin_prefetch((data + 32*i + 384), 0 , 3 );

      for (size_t j = 0; j < 2; ++j, ++i) {
         __m256i const x = _mm256_loadu_si256(input + i);
         __m256i const a = _mm256_loadu_si256(_random + i);

         // Vector add x+a mod 2^32.
         // In contrast to mul, there is no epu version.
         // We actually add in 64 bit chunks, for consistency with
         // non-avx version.
         __m256i const tmp  = _mm256_add_epi64(x, a);
         //__m256i const tmp  = _mm256_add_epi32(x, a);

         // Align high values into low values, to prepare for pair multiplication
         __m256i const tmp2 = _mm256_srli_epi64(tmp, 32);
         // An alternative using shuffeling
         //__m256i const tmp2 = shuffle_epi32(tmp, _MM_SHUFFLE(0, 3, 0, 1));

         // Multiplies the value of packed unsigned doubleword integer
         // in source vector s1 by the value in source vector s2 and stores
         // the result in the destination vector.
         // When a quadword result is too large to be represented in 64 bits
         // (overflow), the result is wrapped around and the low 64 bits are
         // written to the destination element (that is, the carry is ignored).
         __m256i const product =  _mm256_mul_epu32(tmp, tmp2);
         acc = _mm256_add_epi64(acc, product);
      }
   }
   uint64_t x[4];
   memcpy(&x, &acc, sizeof(x));
   return x[0] + x[1] + x[2] + x[3];
}
#endif

static uint64_t TAB_BLOCK_scalar_nh32(const uint64_t* random, const uint8_t* data) {
   uint64_t block_hash = 0;
   for (size_t i = 0; i < TAB_BLOCK_LENGTH; i++) {
      // Parallel addition helps auto-vectorization
      uint64_t k = TAB_take_8(&data);
      uint64_t x = random[i] + k;
      block_hash += (x >> 32)*(uint32_t)x;
   }
   return block_hash;
}


////////////////////////////////////////////////////////////////////////////////
// Main hash functions
////////////////////////////////////////////////////////////////////////////////


uint64_t TAB_universal(TAB_hash* hash, const uint8_t* bytes, size_t len_bytes) {

   // Make a non-const version of the pointer, so we can move it along as we go.
   const uint8_t* data = bytes;

   // Add a character for the length to prevent length extension attacks.
   uint64_t val = len_bytes;

   if (len_bytes >= 8) {
      int len_words = len_bytes / 8;

      while (len_words >= TAB_BLOCK_LENGTH) {
         #if TAB_VECTOR == TAB_AVX2
            uint64_t block_hash = TAB_BLOCK_vector_nh32(hash->nh_table, data);
         #else
            uint64_t block_hash = TAB_BLOCK_scalar_nh32(hash->nh_table, data);
         #endif

         // Add to variable-length hash as two characters to fit under Mersenne 61.
         // Note that the "bottle-neck" is still 32 bits.
         uint32_t x[2];
         memcpy(&x, &block_hash, sizeof(x));
         val = TAB_combine61(val, x[0], hash->alpha);
         val = TAB_combine61(val, x[1], hash->alpha);

         // The block hashes don't automatically increment data
         data += 8*TAB_BLOCK_LENGTH;
         len_words -= TAB_BLOCK_LENGTH;
      }

      for (size_t i = 0; i < len_words; ++i)
         val += hash->ms_table[i] * TAB_take_8(&data) >> 64;
   }

   int remaining_bytes = len_bytes % 8;
   if (remaining_bytes) {
      uint64_t last = TAB_take_n(&data, remaining_bytes);
      val += (hash->ms_extra * last) >> 64;
   }

   return val;
}

uint64_t TAB_process(TAB_hash* hash, const uint8_t* const bytes, size_t len_bytes, uint64_t state) {
   uint64_t val = TAB_universal(hash, bytes, len_bytes);
   // Do we need a value independent of alpha here?
   return TAB_combine61(state, val, hash->alpha);
}

uint64_t TAB_process_64(TAB_hash_64* hash, const uint8_t* const bytes, size_t len_bytes, uint64_t state) {
   return 0;
}

uint64_t TAB_finalize(TAB_hash* hash, uint64_t state) {
   uint8_t x[8];
   memcpy(&x, &state, sizeof(x));
   uint64_t res = 0;
   for (int i = 0; i < 8; i++)
      res ^= hash->tab_table[i][x[i]];
   return res;
}

uint64_t TAB_finalize_64(TAB_hash_64* hash, uint64_t state) {
   return 0;
}
