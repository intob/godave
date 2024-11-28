// +build amd64

#include "textflag.h"

// func xorInto(dst, a, b []byte)
TEXT ·xorInto(SB), NOSPLIT, $0-72
    MOVQ dst+0(FP), DI         // Load dst slice base address
    MOVQ a+24(FP), SI          // Load a slice base address
    MOVQ b+48(FP), DX          // Load b slice base address
    
    // Process first 16 bytes
    MOVOU (SI), X0             // Load first 16 bytes from a
    MOVOU (DX), X1             // Load first 16 bytes from b
    PXOR X1, X0                // XOR first 16 bytes
    MOVOU X0, (DI)             // Store first 16 bytes to dst
    
    // Process second 16 bytes
    MOVOU 16(SI), X0           // Load second 16 bytes from a
    MOVOU 16(DX), X1           // Load second 16 bytes from b
    PXOR X1, X0                // XOR second 16 bytes
    MOVOU X0, 16(DI)           // Store second 16 bytes to dst
    
    RET
