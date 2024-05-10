#if defined (__cplusplus)
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>  /* size_t */
#include <string.h>  /* memcpy() */


#define TAB_SEED_LENGTH 100
#define TAB_BLOCK_LENGTH 256

static uint64_t TAB_DEFAULT_SEED[TAB_SEED_LENGTH] = {
0x3c51f59614df8a4e, 0xd38e56220364703c, 0x1b8ff26a4a188aed, 0xc59b0d7f836e91a8, 0x815bf80d8e85ef70, 0x5368e47c32bdceb9, 0x8d8a1578232db440, 0x69a29000bd99c037, 0xb7dc14fc00151ae8, 0x16f10540b9a572fe, 0x4214b34341c0b667, 0xe2ed2889a16f554d, 0x98ea7e121253142e, 0x8a8d412a134fbb2c, 0xf6c04e1f3ad202cf, 0xc8f8af67cb2f6870, 0x71b7df358abd5e96, 0x36453921d7bf801d, 0xe092578a2b1cd8f9, 0xd885a967e027c3b8, 0xe05f9a7375570c69, 0x670c6b2c2b1b2e7, 0x8261bdeaaa496815, 0x6f1feabdafe652d5, 0xd697c85ebd433036, 0xf436706b93baf4a6, 0x359a18d8771412cc, 0xfd4275e19ace3370, 0xb55c7c2b1dd8e1cf, 0xee6f8dbf46aa5f70, 0x2fe63a85edbeec78, 0x8b682498b806af29, 0xff13b57050a2b3b5, 0x6f00e8a0161d8ef2, 0xf707964a73959fa8, 0x85363922a6db83c9, 0x1dda23058b3c2c81, 0x46ab407de512a2cc, 0x26ce74b42be92a4a, 0x2d5f106c90682fa8, 0xbd521be1b7623a55, 0xb1dff7c5fae8507a, 0x3f4c046beb3209d9, 0x4693eb573921a739, 0xcce9db92fc07e453, 0xfd717d0c0e9603b5, 0xf74a05e291b40a3a, 0x74590ba41f377c1e, 0x1bba8bd73f96a38b, 0x2979a6899a846af5, 0x5905422dc399e23b, 0x41563ced10d532bf, 0xe62ee7c966029937, 0xf3f61a3b0c74044, 0xe9ef7865ff01cd21, 0x575235643749bd6f, 0xd250d09d31615476, 0x65b7ecf617fd047e, 0x62afe6bddb25e897, 0xd7e9552aa6c34fad, 0x48cff43fa5ba6437, 0x9111d8b0a36a2bc2, 0xf2087c34fdc07d35, 0x6225d3c92522b08e, 0xc4fb1750fcd762b1, 0x4f84a313b0be20e5, 0x725d3f81c4c33c82, 0xd3ae82911d5e2776, 0xddff8f3742c79329, 0x835e6fe9d932f2d0, 0x53f1065cc9320085, 0x7a6a4ee44d0539e7, 0x9bfbdf71cdd77da7, 0xb0855fbe28e96e5e, 0x898bc52406950107, 0x9d5ffd3b37844f82, 0x7031f6cb6021305, 0xff493017348ab40a, 0xa3c3d954d3b4b0c5, 0x57f1986aec746aad};

struct TAB_generator {
   // TODO: We could also let the user decide how many words they want to add.
   // Then we just store a pointer and a length and run the polynomial as deep
   // as needed.
   // Remember: If we store pointers in structs, we need to provide a free_generator
   // function to allow releasing the data.
   uint64_t seed[TAB_SEED_LENGTH];
};
typedef struct TAB_generator TAB_generator;

/*
 * Instantiate the random generator.
 */
void TAB_init_generator(TAB_generator* gen, uint64_t seed[TAB_SEED_LENGTH]);

// TODO: Would
// tab_generator* tab_new_generator(seed);
// Be a better API?

/*
 * Produce a single random value using the generator.
 * Can also be used as a single (strong) hash function h(x).
 */
uint64_t TAB_generate(TAB_generator* gen, uint64_t x);

struct TAB_hash {
   uint64_t nh_table[TAB_BLOCK_LENGTH];
   uint64_t tab_table[8][256];
   __uint128_t ms_table[TAB_BLOCK_LENGTH];
   uint64_t alpha;
   __uint128_t ms_extra;
};
typedef struct TAB_hash TAB_hash;

// More randomness for more security
struct TAB_hash_64 {
   uint64_t nh_table[TAB_BLOCK_LENGTH];
   uint64_t tab_table[8][256];
   __uint128_t ms_table[TAB_BLOCK_LENGTH];
   uint64_t alpha;
   __uint128_t ms_extra;
};
typedef struct TAB_hash_64 TAB_hash_64;

struct TAB_hash_128 {
   uint64_t utable[TAB_BLOCK_LENGTH];
   uint64_t ftable[8][256];
};
typedef struct TAB_hash_128 TAB_hash_128;

/*
 * Initialize hash function using a generator and a seed.
 * The hash functions will be 100-independent, which is enough for nearly
 * anything - Jakob can you add something here?
 */
void TAB_init_hash(TAB_hash* hash, TAB_generator* gen, uint64_t seed);
void TAB_init_hash_64(TAB_hash_64* hash, TAB_generator* gen, uint64_t seed);

/*
 * Process `len` bytes and return a state for further processing.
 * Can be called with `state = 0` when run the first time.
 * TODO: Is a single 64bit number enough state? Maybe we need to keep the length
 * to prevent extension attacks? Or can we just add the given individual lengths
 * as separate characters? That sounds fine to me. It's also nice that the partial
 * state is always a universal hash of what we've seen so far.
 */
uint64_t TAB_process(TAB_hash* hash, const uint8_t* bytes, size_t len_bytes, uint64_t state);
uint64_t TAB_process_64(TAB_hash_64* hash, const uint8_t* bytes, size_t len_bytes, uint64_t state);

/*
 * Apply a strong hash to the state.
 */
uint64_t TAB_finalize(TAB_hash* hash, uint64_t state);
uint64_t TAB_finalize_64(TAB_hash_64* hash, uint64_t state);

/*
 * Convenience function for hashing a single value.
 * TODO: Is this actually different from calling tab_finalize(x)?
 *       Yes.. Because _finalize does ony tabulation, and that's not enough.
 */
static uint64_t TAB_hash_single(TAB_hash* hash, uint64_t x) {
   uint8_t bytes[8];
   memcpy(bytes, &x, sizeof(x));
   uint64_t state = TAB_process(hash, bytes, 8, 0);
   return TAB_finalize(hash, state);
}


#if defined (__cplusplus)
}
#endif
