// SPDX-License-Identifier: MIT
//arm lock helper
//there is 2 part: read and write
// write return 0 on success, 1 on fail (value has been changed)

.text
.align 4

.extern cpuext
.global arm64_lock_read_b
.global arm64_lock_write_b
.global arm64_lock_read_h
.global arm64_lock_write_h
.global arm64_lock_read_d
.global arm64_lock_write_d
.global arm64_lock_read_dd
.global arm64_lock_write_dd
.global arm64_lock_read_dq
.global arm64_lock_write_dq
.global arm64_lock_xadd_unaligned
.global arm64_lock_rmw_unaligned
.global arm64_lock_xchg_dd
.global arm64_lock_xchg_d
.global arm64_lock_xchg_h
.global arm64_lock_xchg_b
.global arm64_lock_storeifnull
.global arm64_lock_storeifnull_d
.global arm64_lock_storeifref
.global arm64_lock_storeifref2
.global arm64_lock_storeifref_d
.global arm64_lock_storeifref2_d
.global arm64_lock_decifnot0b
.global arm64_lock_storeb
.global arm64_lock_incif0
.global arm64_lock_inc
.global arm64_lock_decifnot0
.global arm64_lock_store
.global arm64_lock_store_dd
.global arm64_lock_get_b
.global arm64_lock_get_d
.global arm64_lock_get_dd
.global arm64_crc
.global arm64_x31_hash

arm64_lock_read_b:
    dmb     ish
    // address is x0, return is x0
    ldaxrb  w0, [x0]
    ret

// x1: address, x2: addend, w3: size (2, 4 or 8).
// The caller checks that the field fits in one aligned 16-byte block.
// Update its containing word/pair exclusively, preserving surrounding bytes.
#ifndef _WIN32
.type arm64_lock_xadd_unaligned, %function
#endif
arm64_lock_xadd_unaligned:
    dmb     ish
    and     x4, x1, #-8
    and     x5, x1, #7
    add     x7, x5, x3
    lsl     x5, x5, #3
    lsl     x6, x3, #3
    neg     x6, x6
    mov     x3, #-1
    lsr     x6, x3, x6       // field mask, including the 64-bit case
    cmp     x7, #8
    b.hi    2f
    lsl     x7, x6, x5       // mask in the containing word
1:
    ldaxr   x8, [x4]
    lsr     x0, x8, x5
    and     x0, x0, x6
    add     x9, x0, x2
    and     x9, x9, x6
    bic     x10, x8, x7
    lsl     x9, x9, x5
    orr     x10, x10, x9
    stlxr   w11, x10, [x4]
    cbnz    w11, 1b
    dmb     ish
    ret
2:
    // Crossing the middle of the block: x4 is now 16-byte aligned,
    // and the shift is strictly between 0 and 64.
    neg     x7, x5
    lsl     x12, x6, x5      // low half of the field mask
    lsr     x13, x6, x7      // high half of the field mask
3:
    ldaxp   x8, x9, [x4]
    lsr     x0, x8, x5
    lsl     x10, x9, x7
    orr     x0, x0, x10
    and     x0, x0, x6
    add     x10, x0, x2
    and     x10, x10, x6
    bic     x8, x8, x12
    lsl     x11, x10, x5
    orr     x8, x8, x11
    bic     x9, x9, x13
    lsr     x11, x10, x7
    orr     x9, x9, x11
    stlxp   w14, x8, x9, [x4]
    cbnz    w14, 3b
    dmb     ish
    ret
#ifndef _WIN32
.size arm64_lock_xadd_unaligned, .-arm64_lock_xadd_unaligned
#endif

// Operation numbers match arm64_rmw_op_t in arm64_lock.h.
.macro RMW_SELECT kind
    cbz     w15, .Lrmw_\kind\()_add
    cmp     w15, #1
    b.eq    .Lrmw_\kind\()_or
    cmp     w15, #2
    b.eq    .Lrmw_\kind\()_adc
    cmp     w15, #3
    b.eq    .Lrmw_\kind\()_and
    cmp     w15, #4
    b.eq    .Lrmw_\kind\()_xchg
    cmp     w15, #5
    b.eq    .Lrmw_\kind\()_cmpxchg
    cmp     w15, #6
    b.eq    .Lrmw_\kind\()_sub
    cmp     w15, #7
    b.eq    .Lrmw_\kind\()_xor
    brk     #0
.endm

.macro RMW_VALUE out, op
    .ifc \op,add
        add     \out, x0, x2
    .endif
    .ifc \op,or
        orr     \out, x0, x2
    .endif
    .ifc \op,adc
        add     \out, x0, x2
        add     \out, \out, x16
    .endif
    .ifc \op,and
        and     \out, x0, x2
    .endif
    .ifc \op,xchg
        mov     \out, x2
    .endif
    .ifc \op,cmpxchg
        cmp     x0, x16
        csel    \out, x2, x0, eq
    .endif
    .ifc \op,sub
        sub     \out, x0, x2
    .endif
    .ifc \op,xor
        eor     \out, x0, x2
    .endif
.endm

// x0: unused emu, x1: field address, x2: value, w3: size,
// w4: operation, x5: carry-in / expected value. Return old field in x0.
// The caller verifies that the field fits inside one aligned 16-byte block.
#ifndef _WIN32
.type arm64_lock_rmw_unaligned, %function
#endif
arm64_lock_rmw_unaligned:
    dmb     ish
    mov     w15, w4
    mov     x16, x5
    and     x4, x1, #-8
    and     x5, x1, #7
    add     x7, x5, x3
    lsl     x5, x5, #3
    lsl     x6, x3, #3
    neg     x6, x6
    mov     x3, #-1
    lsr     x6, x3, x6
    and     x2, x2, x6
    and     x16, x16, x6
    cmp     x7, #8
    b.hi    .Lrmw_pair_setup
    lsl     x7, x6, x5
    RMW_SELECT word
.Lrmw_pair_setup:
    neg     x7, x5
    lsl     x12, x6, x5
    lsr     x13, x6, x7
    RMW_SELECT pair

// Dispatch occurs before LDXR/LDXP, keeping each exclusive window short.
.macro RMW_WORD op
.Lrmw_word_\op:
    ldaxr   x8, [x4]
    lsr     x0, x8, x5
    and     x0, x0, x6
    RMW_VALUE x9, \op
    and     x9, x9, x6
    bic     x10, x8, x7
    lsl     x9, x9, x5
    orr     x10, x10, x9
    stlxr   w11, x10, [x4]
    cbnz    w11, .Lrmw_word_\op
    b       .Lrmw_done
.endm

.macro RMW_PAIR op
.Lrmw_pair_\op:
    ldaxp   x8, x9, [x4]
    lsr     x0, x8, x5
    lsl     x10, x9, x7
    orr     x0, x0, x10
    and     x0, x0, x6
    RMW_VALUE x10, \op
    and     x10, x10, x6
    bic     x8, x8, x12
    lsl     x11, x10, x5
    orr     x8, x8, x11
    bic     x9, x9, x13
    lsr     x11, x10, x7
    orr     x9, x9, x11
    // Validate even a failed CMPXCHG: LDAXP alone can observe a torn pair.
    stlxp   w14, x8, x9, [x4]
    cbnz    w14, .Lrmw_pair_\op
    b       .Lrmw_done
.endm

    RMW_WORD add
    RMW_WORD or
    RMW_WORD adc
    RMW_WORD and
    RMW_WORD xchg
    RMW_WORD cmpxchg
    RMW_WORD sub
    RMW_WORD xor
    RMW_PAIR add
    RMW_PAIR or
    RMW_PAIR adc
    RMW_PAIR and
    RMW_PAIR xchg
    RMW_PAIR cmpxchg
    RMW_PAIR sub
    RMW_PAIR xor
.Lrmw_done:
    dmb     ish
    ret
#ifndef _WIN32
.size arm64_lock_rmw_unaligned, .-arm64_lock_rmw_unaligned
#endif
.purgem RMW_SELECT
.purgem RMW_VALUE
.purgem RMW_WORD
.purgem RMW_PAIR

arm64_lock_write_b:
    // address is x0, value is x1, return is x0
    mov     x2, x0
    stlxrb  w0, w1, [x2]
    dmb     ish
    ret

arm64_lock_read_h:
    dmb     ish
    // address is x0, return is x0
    ldaxrh  w0, [x0]
    ret

arm64_lock_write_h:
    // address is x0, value is x1, return is x0
    mov     x2, x0
    stlxrh  w0, w1, [x2]
    dmb     ish
    ret

arm64_lock_read_d:
    dmb     ish
    // address is x0, return is x0
    ldaxr    w0, [x0]
    ret

arm64_lock_write_d:
    // address is x0, value is w1, return is x0
    mov     x2, x0
    stlxr   w0, w1, [x2]
    dmb     ish
    ret

arm64_lock_read_dd:
    dmb     ish
    // address is x0, return is x0
    ldaxr   x0, [x0]
    ret

arm64_lock_write_dd:
    // address is x0, value is x1, return is x0
    mov     x2, x0
    stlxr   w0, x1, [x2]
    dmb     ish
    ret

arm64_lock_read_dq:
    dmb     ish
    // address is r2, return is r0, r1
    ldaxp   x4, x3, [x2]
    str     x4, [x0]
    str     x3, [x1]
    ret

arm64_lock_write_dq:
    // address is r2, value is r0, r1, return is r0
    // r0 needs to be aligned
    stlxp   w3, x0, x1, [x2]
    mov     w0, w3
    dmb     ish
    ret


arm64_lock_xchg_dd:
    adrp    x3, cpuext
    add     x3, x3, #:lo12:cpuext
    ldr     w3, [x3]
    tbnz    w3, #0, arm64_atomic_xchg_dd
    dmb     ish
arm64_lock_xchg_dd_0:
    // address is x0, value is x1, return old value in x0
    ldaxr   x2, [x0]
    stlxr   w3, x1, [x0]
    cbnz    w3, arm64_lock_xchg_dd_0
    mov     x0, x2
    ret

arm64_atomic_xchg_dd:
    dmb     ish
    // address is x0, value is x1, return old value in x0
    swpal   x1, x0, [x0]
    ret

arm64_lock_xchg_d:
    adrp    x3, cpuext
    add     x3, x3, #:lo12:cpuext
    ldr     w3, [x3]
    tbnz    w3, #0, arm64_atomic_xchg_d
    dmb     ish
arm64_lock_xchg_d_0:
    // address is x0, value is x1, return old value in x0
    ldaxr   w2, [x0]
    stlxr   w3, w1, [x0]
    cbnz    w3, arm64_lock_xchg_d_0
    mov     w0, w2
    ret

arm64_atomic_xchg_d:
    dmb     ish
    // address is x0, value is x1, return old value in x0
    swpal   w1, w0, [x0]
    ret

arm64_lock_xchg_h:
    adrp    x3, cpuext
    add     x3, x3, #:lo12:cpuext
    ldr     w3, [x3]
    tbnz    w3, #0, arm64_atomic_xchg_h
    dmb     ish
arm64_lock_xchg_h_0:
    // address is x0, value is x1, return old value in x0
    ldaxrh  w2, [x0]
    stlxrh  w3, w1, [x0]
    cbnz    w3, arm64_lock_xchg_h_0
    mov     w0, w2
    ret

arm64_atomic_xchg_h:
    dmb     ish
    // address is x0, value is x1, return old value in x0
    swpalh  w1, w0, [x0]
    ret

arm64_lock_xchg_b:
    adrp    x3, cpuext
    add     x3, x3, #:lo12:cpuext
    ldr     w3, [x3]
    tbnz    w3, #0, arm64_atomic_xchg_b
    dmb     ish
arm64_lock_xchg_b_0:
    // address is x0, value is x1, return old value in x0
    ldaxrb   w2, [x0]
    stlxrb   w3, w1, [x0]
    cbnz    w3, arm64_lock_xchg_b_0
    mov     w0, w2
    ret

arm64_atomic_xchg_b:
    dmb     ish
    // address is x0, value is x1, return old value in x0
    swpalb  w1, w0, [x0]
    ret

arm64_lock_storeifnull:
    adrp    x3, cpuext
    add     x3, x3, #:lo12:cpuext
    ldr     w3, [x3]
    tbnz    w3, #0, arm64_atomic_storeifnull
    dmb     ish
1:
    // address is x0, value is x1, x1 store to x0 only if [x0] is 0. return old [x0] value
    ldaxr   x2, [x0]
    cbnz    x2, 2f
    stlxr   w3, x1, [x0]
    cbnz    w3, 1b
2:
    mov     x0, x2
    ret

arm64_atomic_storeifnull:
    dmb     ish
    // address is x0, value is x1, x1 store to x0 only if [x0] is 0. return old [x0] value
    mov     x2, xzr
    casal   x2, x1, [x0]
    mov     x0, x2
    ret


arm64_lock_storeifnull_d:
    adrp    x3, cpuext
    add     x3, x3, #:lo12:cpuext
    ldr     w3, [x3]
    tbnz    w3, #0, arm64_atomic_storeifnull_d
    dmb     ish
1:
    // address is x0, value is w1, w1 store to x0 only if [x0] is 0. return old [x0] value
    ldaxr   w2, [x0]
    cbnz    w2, 2f
    stlxr   w3, w1, [x0]
    cbnz    w3, 1b
2:
    dmb     ish
    mov     w0, w2
    ret

arm64_atomic_storeifnull_d:
    dmb     ish
    // address is x0, value is w1, w1 store to x0 only if [x0] is 0. return old [x0] value
    mov     x2, xzr
    casal   w2, w1, [x0]
    mov     w0, w2
    ret

arm64_lock_storeifref:
    adrp    x3, cpuext
    add     x3, x3, #:lo12:cpuext
    ldr     w3, [x3]
    tbnz    w3, #0, arm64_atomic_storeifref
    dmb     ish
1:
    // address is x0, value is x1, x1 store to x0 only if [x0] is x2. return new [x0] value (so x1 or old value)
    ldaxr   x3, [x0]
    cmp     x2, x3
    bne     2f
    stlxr   w4, x1, [x0]
    cbnz    w4, 1b
    mov     x0, x1
    ret
2:
    mov     x0, x3
    ret

arm64_atomic_storeifref:
    dmb     ish
    // address is x0, value is x1, x1 store to x0 only if [x0] is x2. return new [x0] value (so x1 or old value)
    mov     x3, x2
    casal   x2, x1, [x0]
    cmp     x2, x3
    bne     2f
    mov     x0, x1
    ret
2:
    mov     x0, x3
    ret

arm64_lock_storeifref_d:
    adrp    x3, cpuext
    add     x3, x3, #:lo12:cpuext
    ldr     w3, [x3]
    tbnz    w3, #0, arm64_atomic_storeifref_d
    dmb     ish
1:
    // address is x0, value is w1, w1 store to x0 only if [x0] is w2. return new [x0] value (so x1 or old value)
    ldaxr   w3, [x0]
    cmp     w2, w3
    bne     2f
    stlxr   w4, w1, [x0]
    cbnz    w4, 1b
    mov     w0, w1
    ret
2:
    mov     w0, w3
    ret

arm64_atomic_storeifref_d:
    dmb     ish
    // address is x0, value is w1, w1 store to x0 only if [x0] is w2. return new [x0] value (so w1 or old value)
    mov     w3, w2
    casal   w2, w1, [x0]
    bne     2f
    cmp     w2, w3
    mov     w0, w1
    ret
2:
    mov     w0, w3
    ret

arm64_lock_storeifref2_d:
    adrp    x3, cpuext
    add     x3, x3, #:lo12:cpuext
    ldr     w3, [x3]
    tbnz    w3, #0, arm64_atomic_storeifref2_d
    dmb     ish
1:
    // address is x0, value is w1, w1 store to x0 only if [x0] is w2. return old [x0] value
    ldaxr   w3, [x0]
    cmp     w2, w3
    bne     2f
    stlxr   w4, w1, [x0]
    cbnz    w4, 1b
2:
    mov     w0, w3
    ret

arm64_atomic_storeifref2_d:
    dmb     ish
    // address is x0, value is w1, w1 store to x0 only if [x0] is w2. return old [x0] value
    casal   w2, w1, [x0]
    mov     w0, w2
    ret

arm64_lock_storeifref2:
    adrp    x3, cpuext
    add     x3, x3, #:lo12:cpuext
    ldr     w3, [x3]
    tbnz    w3, #0, arm64_atomic_storeifref2
    dmb     ish
1:
    // address is x0, value is x1, x1 store to x0 only if [x0] is x2. return old [x0] value
    ldaxr   x3, [x0]
    cmp     x2, x3
    bne     2f
    stlxr   w4, x1, [x0]
    cbnz    w4, 1b
2:
    mov     x0, x3
    ret

arm64_atomic_storeifref2:
    dmb     ish
    // address is x0, value is x1, x1 store to x0 only if [x0] is x2. return old [x0] value
    casal   x2, x1, [x0]
    mov     x0, x2
    ret

arm64_lock_decifnot0b:
    dmb     ish
1:
    ldaxrb  w1, [x0]
    cmp     w1, #0
    beq     2f
    sub     w1, w1, #1
    stlxrb  w2, w1, [x0]
    cbnz    w2, 1b
2:
    ret

arm64_lock_storeb:
    strb    w1, [x0]
    dmb     ish
    ret

arm64_lock_decifnot0:
    dmb     ish
1:
    ldaxr   w1, [x0]
    cmp     w1, #0
    beq     2f
    sub     w3, w1, #1
    stlxr   w2, w3, [x0]
    cbnz    w2, 1b
2:
    mov     w0, w1
    ret

arm64_lock_incif0:
    adrp    x3, cpuext
    add     x3, x3, #:lo12:cpuext
    ldr     w3, [x3]
    tbnz    w3, #0, arm64_atomic_incif0
    dmb     ish
1:
    ldaxr   w1, [x0]
    cmp     w1, #0
    bne     2f
    add     w3, w1, #1
    stlxr   w2, w3, [x0]
    cbnz    w2, 1b
2:
    mov     w0, w1
    ret

arm64_atomic_incif0:
    mov     w1, #1
    dmb     ish
    swpal   w1, wzr, [x0]
    mov     w0, w1
    ret

arm64_lock_inc:
    adrp    x3, cpuext
    add     x3, x3, #:lo12:cpuext
    ldr     w3, [x3]
    tbnz    w3, #0, arm64_atomic_inc
    dmb     ish
1:
    ldaxr   w1, [x0]
    add     w3, w1, #1
    stlxr   w2, w3, [x0]
    cbnz    w2, 1b
2:
    mov     w0, w1
    ret

arm64_atomic_inc:
    mov     w1, #1
    dmb     ish
    ldadd   w1, w2, [x0]
    mov     w0, w2
    ret

arm64_lock_store:
    str     w1, [x0]
    dmb     ish
    ret

arm64_lock_store_dd:
    str     x1, [x0]
    dmb     ish
    ret

arm64_lock_get_b:
    ldaxrb  w0, [x0]
    ret

arm64_lock_get_d:
    ldaxr   w0, [x0]
    ret

arm64_lock_get_dd:
    ldaxr   x0, [x0]
    ret

arm64_crc:
    //x0 is address, w1 is len
    mov     x2, x0  // address is x2 now
    mov     w0, wzr // crc is w0
1:
    cmp     w1, #8
    blo     2f
    ldr     x3, [x2], #8
    crc32x  w0, w0, x3
    subs    w1, w1, #8
    bne     1b
2:
    cbz     w1, 4f
3:
    ldrb    w3, [x2], #1
    crc32b  w0, w0, w3
    subs    w1, w1, #1
    bne     3b
4:
    ret

arm64_x31_hash:
    //x0 is address, w1 is len
    mov     x2, x0  // address is x2 now
    mov     w0, wzr // hash is w0
1:
    cmp     w1, #8
    blo     2f
    ldr     x3, [x2], #8
    mov     x4, #8
3:
    sub     w0, w0, w0, lsl #5
    sub     w0, w0, w3, uxtb
    sub     w0, wzr, w0
    ror     x3, x3, #8
    subs    w4, w4, #1
    bne    3b
2:
    cbz     w1, 5f
4:
    ldrb    w3, [x2], #1
    sub     w0, w0, w0, lsl #5
    sub     w0, w3, w0
    subs    w1, w1, #1
    bne     4b
5:
    ret
