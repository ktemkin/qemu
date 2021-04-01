/*
 * Tiny Code Generator for QEMU
 *
 * Copyright (c) 2009, 2011 Stefan Weil
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/*
 * This code implements a TCG which does not generate machine code for some
 * real target machine but which generates virtual machine code for an
 * interpreter. Interpreted pseudo code is slow, but it works on any host.
 *
 * Some remarks might help in understanding the code:
 *
 * "target" or "TCG target" is the machine which runs the generated code.
 * This is different to the usual meaning in QEMU where "target" is the
 * emulated machine. So normally QEMU host is identical to TCG target.
 * Here the TCG target is a virtual machine, but this virtual machine must
 * use the same word size like the real machine.
 * Therefore, we need both 32 and 64 bit virtual machines (interpreter).
 */

#ifndef TCG_TARGET_H
#define TCG_TARGET_H

#if UINTPTR_MAX == UINT32_MAX
# error We only support AArch64 running in 64B mode.
#elif UINTPTR_MAX == UINT64_MAX
# define TCG_TARGET_REG_BITS 64
#else
# error Unknown pointer size for tcti target
#endif

#define TCG_TARGET_INSN_UNIT_SIZE        1
#define TCG_TARGET_TLB_DISPLACEMENT_BITS 32

// We're an interpreted target; even if we're JIT-compiling to our interpreter's
// weird psuedo-native bytecode. We'll indicate that we're intepreted.
#define TCG_TARGET_INTERPRETER 1

//
// Supported optional instructions.
//

// Divs.
#define TCG_TARGET_HAS_div_i32          1
#define TCG_TARGET_HAS_rem_i32          1
#define TCG_TARGET_HAS_div_i64          1
#define TCG_TARGET_HAS_rem_i64          1

// Extends.
#define TCG_TARGET_HAS_ext8s_i32        1
#define TCG_TARGET_HAS_ext16s_i32       1
#define TCG_TARGET_HAS_ext8u_i32        1
#define TCG_TARGET_HAS_ext16u_i32       1
#define TCG_TARGET_HAS_ext8s_i64        1
#define TCG_TARGET_HAS_ext16s_i64       1
#define TCG_TARGET_HAS_ext32s_i64       1
#define TCG_TARGET_HAS_ext8u_i64        1
#define TCG_TARGET_HAS_ext16u_i64       1
#define TCG_TARGET_HAS_ext32u_i64       1

// Logicals.
#define TCG_TARGET_HAS_neg_i32          1
#define TCG_TARGET_HAS_not_i32          1
#define TCG_TARGET_HAS_neg_i64          1
#define TCG_TARGET_HAS_not_i64          1

#define TCG_TARGET_HAS_andc_i32         1
#define TCG_TARGET_HAS_orc_i32          1
#define TCG_TARGET_HAS_eqv_i32          1
#define TCG_TARGET_HAS_andc_i64         1
#define TCG_TARGET_HAS_eqv_i64          1
#define TCG_TARGET_HAS_orc_i64          1

// We don't curretly support rotates, since AArch64 lacks ROL.
// We'll fix this later.
#define TCG_TARGET_HAS_rot_i32          0
#define TCG_TARGET_HAS_rot_i64          0

// Swaps.
#define TCG_TARGET_HAS_bswap16_i32      1
#define TCG_TARGET_HAS_bswap32_i32      1
#define TCG_TARGET_HAS_bswap16_i64      1
#define TCG_TARGET_HAS_bswap32_i64      1
#define TCG_TARGET_HAS_bswap64_i64      1
#define TCG_TARGET_HAS_MEMORY_BSWAP     1

// Specify we'll handle direct jumps.
#define TCG_TARGET_HAS_direct_jump      1

//
// Potential TODOs.
//

// TODO: implement DEPOSIT as BFI.
#define TCG_TARGET_HAS_deposit_i32      0
#define TCG_TARGET_HAS_deposit_i64      0

// TODO: implement EXTRACT as BFX.
#define TCG_TARGET_HAS_extract_i32      0
#define TCG_TARGET_HAS_sextract_i32     0
#define TCG_TARGET_HAS_extract_i64      0
#define TCG_TARGET_HAS_sextract_i64     0

// TODO: it might be worth writing a gadget for this
#define TCG_TARGET_HAS_movcond_i32      0
#define TCG_TARGET_HAS_movcond_i64      0

//
// Unsupported instructions.
//

// ARMv8 doesn't have instructions for NAND/NOR.
#define TCG_TARGET_HAS_nand_i32         0
#define TCG_TARGET_HAS_nor_i32          0
#define TCG_TARGET_HAS_nor_i64          0
#define TCG_TARGET_HAS_nand_i64         0

// aarch64's CLZ is implemented without a condition, so it
#define TCG_TARGET_HAS_clz_i32          0
#define TCG_TARGET_HAS_ctz_i32          0
#define TCG_TARGET_HAS_ctpop_i32        0
#define TCG_TARGET_HAS_clz_i64          0
#define TCG_TARGET_HAS_ctz_i64          0
#define TCG_TARGET_HAS_ctpop_i64        0


// GOTO_PTR is too complex to emit a simple gadget for.
// We'll let C handle it, since the overhead is similar.
#define TCG_TARGET_HAS_goto_ptr         0

// We don't have a simple gadget for this, since we're always assuming softmmu.
#define TCG_TARGET_HAS_qemu_st8_i32     0

// No AArch64 equivalent.a
#define TCG_TARGET_HAS_extrl_i64_i32    0
#define TCG_TARGET_HAS_extrh_i64_i32    0

#define TCG_TARGET_HAS_extract2_i64     0

// These should always be zero on our 64B platform.
#define TCG_TARGET_HAS_muls2_i64        0
#define TCG_TARGET_HAS_add2_i32         0
#define TCG_TARGET_HAS_sub2_i32         0
#define TCG_TARGET_HAS_mulu2_i32        0
#define TCG_TARGET_HAS_add2_i64         0
#define TCG_TARGET_HAS_sub2_i64         0
#define TCG_TARGET_HAS_mulu2_i64        0
#define TCG_TARGET_HAS_muluh_i64        0
#define TCG_TARGET_HAS_mulsh_i64        0
#define TCG_TARGET_HAS_extract2_i32     0
#define TCG_TARGET_HAS_muls2_i32        0
#define TCG_TARGET_HAS_muluh_i32        0
#define TCG_TARGET_HAS_mulsh_i32        0

//
// Platform metadata.
//

// Number of registers available.
// It might make sense to up these, since we can also use x16 -> x25?
#define TCG_TARGET_NB_REGS 16

/* List of registers which are used by TCG. */
typedef enum {
    TCG_REG_R0 = 0,
    TCG_REG_R1,
    TCG_REG_R2,
    TCG_REG_R3,
    TCG_REG_R4,
    TCG_REG_R5,
    TCG_REG_R6,
    TCG_REG_R7,
    TCG_REG_R8,
    TCG_REG_R9,
    TCG_REG_R10,
    TCG_REG_R11,
    TCG_REG_R12,
    TCG_REG_R13,
    TCG_REG_R14,
    TCG_REG_R15,

    TCG_AREG0          = TCG_REG_R14,
    TCG_REG_CALL_STACK = TCG_REG_R15,
} TCGReg;

// Specify the shape of the stack our runtime will use.
#define TCG_TARGET_CALL_STACK_OFFSET    0
#define TCG_TARGET_STACK_ALIGN          16

// We're interpreted, so we'll use our own code to run TB_EXEC.
#define HAVE_TCG_QEMU_TB_EXEC

// We'll need to enforce memory ordering with barriers.
#define TCG_TARGET_DEFAULT_MO  (0)

void tci_disas(uint8_t opc);

void tb_target_set_jmp_target(uintptr_t, uintptr_t, uintptr_t, uintptr_t);


#endif /* TCG_TARGET_H */
