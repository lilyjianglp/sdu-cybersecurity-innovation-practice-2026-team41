.arch armv8-a+simd
.text
.align 4

/*
 * Stack layout:
 *   0..95    saved x19..x30
 *   96       state pointer
 *   112..175 temporary bridge for the initial NEON load
 *
 * After the initial load, all sixteen schedule words and A..H remain
 * simultaneously in general-purpose registers.
 */
.equ FRAME_SIZE, 176
.equ STATE_PTR_OFFSET, 96
.equ INPUT_OFFSET, 112

/*
 * Sixteen-word schedule window:
 *
 *   S0..S7   = w0..w7
 *   S8..S15  = w19..w26
 *
 * Compression state:
 *
 *   A..H     = w8..w15
 *
 * Other registers:
 *
 *   w17      = rotated round constant
 *   w16,
 *   w27..w30 = temporaries
 *
 * x18 is intentionally not used because it is platform-reserved on
 * some AArch64 systems.
 */

.macro EXPAND_REG D, R7, R13, R3, R10
    /*
     * D initially holds W[j-16].  It is dead after this expansion and
     * is overwritten with W[j], advancing the circular window.
     */
    eor     \D, \D, \R7
    eor     \D, \D, \R13, ror #17

    eor     w16, \D, \D, ror #17
    eor     w16, w16, \D, ror #9
    eor     w16, w16, \R3, ror #25
    eor     \D, w16, \R10
.endm

.macro ROUND_0_15 W, W4, A, B, C, D, E, F, G, H
    eor     w27, \W, \W4

    ror     w28, \A, #20
    add     w29, w28, \E
    add     w29, w29, w17
    ror     w29, w29, #25
    eor     w30, w29, w28

    eor     w16, \A, \B
    eor     w16, w16, \C

    add     \D, \D, w16

    eor     w16, \E, \F
    eor     w16, w16, \G

    /*
     * Interleave the independent D and H addition chains so that
     * integer execution resources can make progress on both paths.
     */
    add     \H, \H, w16
    add     \D, \D, w30
    add     \H, \H, w29
    add     \D, \D, w27
    add     \H, \H, \W

    ror     \B, \B, #23
    ror     \F, \F, #13

    eor     w16, \H, \H, ror #23
    eor     \H, w16, \H, ror #15
.endm

.macro ROUND_16_63 W, W4, A, B, C, D, E, F, G, H
    eor     w27, \W, \W4

    ror     w28, \A, #20
    add     w29, w28, \E
    add     w29, w29, w17
    ror     w29, w29, #25
    eor     w30, w29, w28

    /*
     * FF = (A & (B XOR C)) XOR (B & C)
     */
    eor     w16, \B, \C
    and     w16, \A, w16
    and     w28, \B, \C
    eor     w16, w16, w28

    add     \D, \D, w16

    /*
     * GG = G XOR (E & (F XOR G))
     */
    eor     w16, \F, \G
    and     w16, \E, w16
    eor     w16, w16, \G

    add     \H, \H, w16
    add     \D, \D, w30
    add     \H, \H, w29
    add     \D, \D, w27
    add     \H, \H, \W

    ror     \B, \B, #23
    ror     \F, \F, #13

    eor     w16, \H, \H, ror #23
    eor     \H, w16, \H, ror #15
.endm

.macro STEP_0_15 W, W4, A, B, C, D, E, F, G, H
    ROUND_0_15 \W, \W4, \A, \B, \C, \D, \E, \F, \G, \H
    ror     w17, w17, #31
.endm

.macro STEP_16_63 W, W4, A, B, C, D, E, F, G, H
    ROUND_16_63 \W, \W4, \A, \B, \C, \D, \E, \F, \G, \H
    ror     w17, w17, #31
.endm

/*
 * Generate W16..W31 and immediately consume rounds 12..27.
 * The first four rounds still use FF0/GG0; the remaining twelve use
 * FF1/GG1.
 */
.macro CYCLE_12_27
    EXPAND_REG w0,  w7,  w24, w3,  w21
    STEP_0_15 w23, w0,  w8,  w9,  w10, w11, w12, w13, w14, w15

    EXPAND_REG w1,  w19, w25, w4,  w22
    STEP_0_15 w24, w1,  w11, w8,  w9,  w10, w15, w12, w13, w14

    EXPAND_REG w2,  w20, w26, w5,  w23
    STEP_0_15 w25, w2,  w10, w11, w8,  w9,  w14, w15, w12, w13

    EXPAND_REG w3,  w21, w0,  w6,  w24
    STEP_0_15 w26, w3,  w9,  w10, w11, w8,  w13, w14, w15, w12

    movz    w17, #0x9d8a
    movk    w17, #0x7a87, lsl #16
    ror     w17, w17, #16

    EXPAND_REG w4,  w22, w1,  w7,  w25
    STEP_16_63 w0,  w4,  w8,  w9,  w10, w11, w12, w13, w14, w15

    EXPAND_REG w5,  w23, w2,  w19, w26
    STEP_16_63 w1,  w5,  w11, w8,  w9,  w10, w15, w12, w13, w14

    EXPAND_REG w6,  w24, w3,  w20, w0
    STEP_16_63 w2,  w6,  w10, w11, w8,  w9,  w14, w15, w12, w13

    EXPAND_REG w7,  w25, w4,  w21, w1
    STEP_16_63 w3,  w7,  w9,  w10, w11, w8,  w13, w14, w15, w12

    EXPAND_REG w19, w26, w5,  w22, w2
    STEP_16_63 w4,  w19, w8,  w9,  w10, w11, w12, w13, w14, w15

    EXPAND_REG w20, w0,  w6,  w23, w3
    STEP_16_63 w5,  w20, w11, w8,  w9,  w10, w15, w12, w13, w14

    EXPAND_REG w21, w1,  w7,  w24, w4
    STEP_16_63 w6,  w21, w10, w11, w8,  w9,  w14, w15, w12, w13

    EXPAND_REG w22, w2,  w19, w25, w5
    STEP_16_63 w7,  w22, w9,  w10, w11, w8,  w13, w14, w15, w12

    EXPAND_REG w23, w3,  w20, w26, w6
    STEP_16_63 w19, w23, w8,  w9,  w10, w11, w12, w13, w14, w15

    EXPAND_REG w24, w4,  w21, w0,  w7
    STEP_16_63 w20, w24, w11, w8,  w9,  w10, w15, w12, w13, w14

    EXPAND_REG w25, w5,  w22, w1,  w19
    STEP_16_63 w21, w25, w10, w11, w8,  w9,  w14, w15, w12, w13

    EXPAND_REG w26, w6,  w23, w2,  w20
    STEP_16_63 w22, w26, w9,  w10, w11, w8,  w13, w14, w15, w12
.endm

/*
 * One complete circular-window rotation.  It generates sixteen new
 * schedule words and immediately consumes the corresponding sixteen
 * compression rounds.
 */
.macro CYCLE_16
    EXPAND_REG w0,  w7,  w24, w3,  w21
    STEP_16_63 w23, w0,  w8,  w9,  w10, w11, w12, w13, w14, w15

    EXPAND_REG w1,  w19, w25, w4,  w22
    STEP_16_63 w24, w1,  w11, w8,  w9,  w10, w15, w12, w13, w14

    EXPAND_REG w2,  w20, w26, w5,  w23
    STEP_16_63 w25, w2,  w10, w11, w8,  w9,  w14, w15, w12, w13

    EXPAND_REG w3,  w21, w0,  w6,  w24
    STEP_16_63 w26, w3,  w9,  w10, w11, w8,  w13, w14, w15, w12

    EXPAND_REG w4,  w22, w1,  w7,  w25
    STEP_16_63 w0,  w4,  w8,  w9,  w10, w11, w12, w13, w14, w15

    EXPAND_REG w5,  w23, w2,  w19, w26
    STEP_16_63 w1,  w5,  w11, w8,  w9,  w10, w15, w12, w13, w14

    EXPAND_REG w6,  w24, w3,  w20, w0
    STEP_16_63 w2,  w6,  w10, w11, w8,  w9,  w14, w15, w12, w13

    EXPAND_REG w7,  w25, w4,  w21, w1
    STEP_16_63 w3,  w7,  w9,  w10, w11, w8,  w13, w14, w15, w12

    EXPAND_REG w19, w26, w5,  w22, w2
    STEP_16_63 w4,  w19, w8,  w9,  w10, w11, w12, w13, w14, w15

    EXPAND_REG w20, w0,  w6,  w23, w3
    STEP_16_63 w5,  w20, w11, w8,  w9,  w10, w15, w12, w13, w14

    EXPAND_REG w21, w1,  w7,  w24, w4
    STEP_16_63 w6,  w21, w10, w11, w8,  w9,  w14, w15, w12, w13

    EXPAND_REG w22, w2,  w19, w25, w5
    STEP_16_63 w7,  w22, w9,  w10, w11, w8,  w13, w14, w15, w12

    EXPAND_REG w23, w3,  w20, w26, w6
    STEP_16_63 w19, w23, w8,  w9,  w10, w11, w12, w13, w14, w15

    EXPAND_REG w24, w4,  w21, w0,  w7
    STEP_16_63 w20, w24, w11, w8,  w9,  w10, w15, w12, w13, w14

    EXPAND_REG w25, w5,  w22, w1,  w19
    STEP_16_63 w21, w25, w10, w11, w8,  w9,  w14, w15, w12, w13

    EXPAND_REG w26, w6,  w23, w2,  w20
    STEP_16_63 w22, w26, w9,  w10, w11, w8,  w13, w14, w15, w12
.endm

.macro CYCLE_4
    EXPAND_REG w0,  w7,  w24, w3,  w21
    STEP_16_63 w23, w0,  w8,  w9,  w10, w11, w12, w13, w14, w15

    EXPAND_REG w1,  w19, w25, w4,  w22
    STEP_16_63 w24, w1,  w11, w8,  w9,  w10, w15, w12, w13, w14

    EXPAND_REG w2,  w20, w26, w5,  w23
    STEP_16_63 w25, w2,  w10, w11, w8,  w9,  w14, w15, w12, w13

    EXPAND_REG w3,  w21, w0,  w6,  w24
    STEP_16_63 w26, w3,  w9,  w10, w11, w8,  w13, w14, w15, w12
.endm

.global sm3_compress_arm64_asm
.type sm3_compress_arm64_asm, %function

sm3_compress_arm64_asm:
    sub     sp, sp, #FRAME_SIZE

    stp     x19, x20, [sp, #0]
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    stp     x25, x26, [sp, #48]
    stp     x27, x28, [sp, #64]
    stp     x29, x30, [sp, #80]
    str     x0, [sp, #STATE_PTR_OFFSET]

    /*
     * SIMD stage: load the complete block and reverse bytes inside
     * each 32-bit word.  The stack is used only once as the deliberate
     * NEON-to-GPR bridge described in the optimization strategy.
     */
    ld1     {v0.16b, v1.16b, v2.16b, v3.16b}, [x1]
    rev32   v0.16b, v0.16b
    rev32   v1.16b, v1.16b
    rev32   v2.16b, v2.16b
    rev32   v3.16b, v3.16b
    add     x16, sp, #INPUT_OFFSET
    st1     {v0.4s, v1.4s, v2.4s, v3.4s}, [x16]

    /*
     * Load A..H before w0 is reused for the schedule window and
     * destroys the incoming state pointer held in x0.
     */
    ldp     w8,  w9,  [x0, #0]
    ldp     w10, w11, [x0, #8]
    ldp     w12, w13, [x0, #16]
    ldp     w14, w15, [x0, #24]

    ldp     w0,  w1,  [x16, #0]
    ldp     w2,  w3,  [x16, #8]
    ldp     w4,  w5,  [x16, #16]
    ldp     w6,  w7,  [x16, #24]
    ldp     w19, w20, [x16, #32]
    ldp     w21, w22, [x16, #40]
    ldp     w23, w24, [x16, #48]
    ldp     w25, w26, [x16, #56]

    movz    w17, #0x4519
    movk    w17, #0x79cc, lsl #16

    /*
     * Rounds 0..11 need only W0..W15, so no expansion is necessary.
     */
    STEP_0_15 w0,  w4,  w8,  w9,  w10, w11, w12, w13, w14, w15
    STEP_0_15 w1,  w5,  w11, w8,  w9,  w10, w15, w12, w13, w14
    STEP_0_15 w2,  w6,  w10, w11, w8,  w9,  w14, w15, w12, w13
    STEP_0_15 w3,  w7,  w9,  w10, w11, w8,  w13, w14, w15, w12

    STEP_0_15 w4,  w19, w8,  w9,  w10, w11, w12, w13, w14, w15
    STEP_0_15 w5,  w20, w11, w8,  w9,  w10, w15, w12, w13, w14
    STEP_0_15 w6,  w21, w10, w11, w8,  w9,  w14, w15, w12, w13
    STEP_0_15 w7,  w22, w9,  w10, w11, w8,  w13, w14, w15, w12

    STEP_0_15 w19, w23, w8,  w9,  w10, w11, w12, w13, w14, w15
    STEP_0_15 w20, w24, w11, w8,  w9,  w10, w15, w12, w13, w14
    STEP_0_15 w21, w25, w10, w11, w8,  w9,  w14, w15, w12, w13
    STEP_0_15 w22, w26, w9,  w10, w11, w8,  w13, w14, w15, w12

    /*
     * Rounds 12..63: generate exactly one new schedule word and
     * immediately consume it as W[j+4].
     */
    CYCLE_12_27
    CYCLE_16
    CYCLE_16
    CYCLE_4

    ldr     x0, [sp, #STATE_PTR_OFFSET]

    ldp     w16, w17, [x0, #0]
    eor     w8, w8, w16
    eor     w9, w9, w17
    stp     w8, w9, [x0, #0]

    ldp     w16, w17, [x0, #8]
    eor     w10, w10, w16
    eor     w11, w11, w17
    stp     w10, w11, [x0, #8]

    ldp     w16, w17, [x0, #16]
    eor     w12, w12, w16
    eor     w13, w13, w17
    stp     w12, w13, [x0, #16]

    ldp     w16, w17, [x0, #24]
    eor     w14, w14, w16
    eor     w15, w15, w17
    stp     w14, w15, [x0, #24]

    ldp     x19, x20, [sp, #0]
    ldp     x21, x22, [sp, #16]
    ldp     x23, x24, [sp, #32]
    ldp     x25, x26, [sp, #48]
    ldp     x27, x28, [sp, #64]
    ldp     x29, x30, [sp, #80]

    add     sp, sp, #FRAME_SIZE
    ret

.size sm3_compress_arm64_asm, .-sm3_compress_arm64_asm

.section .note.GNU-stack,"",%progbits
