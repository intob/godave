// +build arm64

#include "textflag.h"

// func xor256Into(dst, a, b []byte)
TEXT ·xor256Into(SB), NOSPLIT, $0-72
    // Load slice addresses and length
    MOVD dst_base+0(FP), R0   // dst address
    MOVD a_base+24(FP), R1    // a address
    MOVD b_base+48(FP), R2    // b address

    // Load 32 bytes using NEON
    VLD1.P 16(R1), [V0.B16]   // load first 16 bytes of a
    VLD1.P 16(R1), [V1.B16]   // load second 16 bytes of a
    VLD1.P 16(R2), [V2.B16]   // load first 16 bytes of b
    VLD1.P 16(R2), [V3.B16]   // load second 16 bytes of b

    // XOR the vectors
    VEOR V0.B16, V2.B16, V0.B16
    VEOR V1.B16, V3.B16, V1.B16

    // Store result directly into dst
    VST1.P [V0.B16], 16(R0)   // store first 16 bytes
    VST1.P [V1.B16], 16(R0)   // store second 16 bytes

    RET
    