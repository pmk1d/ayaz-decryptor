#pragma once

#include <cstdint>

#ifdef __CUDACC__
#define SALSA_INLINE __host__ __device__ __forceinline__
#else
#define SALSA_INLINE inline
#endif

namespace salsa_search {

struct State {
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7;
    uint32_t x8, x9, x10, x11, x12, x13, x14, x15;
};

SALSA_INLINE uint32_t rotate(uint32_t value, unsigned bits) {
    return (value << bits) | (value >> (32 - bits));
}

SALSA_INLINE void set_byte(State& state, unsigned offset, uint32_t byte) {
    const unsigned shift = (offset & 3U) * 8U;
    const uint32_t mask = ~(uint32_t{255} << shift);
    const uint32_t value = byte << shift;
    switch (offset >> 2U) {
#define BYTE_CASE(i) case i: state.x##i = (state.x##i & mask) | value; break;
        BYTE_CASE(0) BYTE_CASE(1) BYTE_CASE(2) BYTE_CASE(3)
        BYTE_CASE(4) BYTE_CASE(5) BYTE_CASE(6) BYTE_CASE(7)
        BYTE_CASE(8) BYTE_CASE(9) BYTE_CASE(10) BYTE_CASE(11)
        BYTE_CASE(12) BYTE_CASE(13) BYTE_CASE(14) BYTE_CASE(15)
#undef BYTE_CASE
    }
}

SALSA_INLINE State block(const State& initial) {
    State x = initial;
#ifdef __CUDACC__
#pragma unroll
#endif
    for (unsigned round = 0; round < 10; ++round) {
#define QR(a,b,c,d) \
        x.x##b ^= rotate(x.x##a + x.x##d, 7); \
        x.x##c ^= rotate(x.x##b + x.x##a, 9); \
        x.x##d ^= rotate(x.x##c + x.x##b, 13); \
        x.x##a ^= rotate(x.x##d + x.x##c, 18);
        QR(0,4,8,12) QR(5,9,13,1) QR(10,14,2,6) QR(15,3,7,11)
        QR(0,1,2,3) QR(5,6,7,4) QR(10,11,8,9) QR(15,12,13,14)
#undef QR
    }
#define ADD(i) x.x##i += initial.x##i;
    ADD(0) ADD(1) ADD(2) ADD(3) ADD(4) ADD(5) ADD(6) ADD(7)
    ADD(8) ADD(9) ADD(10) ADD(11) ADD(12) ADD(13) ADD(14) ADD(15)
#undef ADD
    return x;
}

SALSA_INLINE void store(const State& state, uint32_t* output) {
#define STORE(i) output[i] = state.x##i;
    STORE(0) STORE(1) STORE(2) STORE(3) STORE(4) STORE(5) STORE(6) STORE(7)
    STORE(8) STORE(9) STORE(10) STORE(11) STORE(12) STORE(13) STORE(14) STORE(15)
#undef STORE
}

}
