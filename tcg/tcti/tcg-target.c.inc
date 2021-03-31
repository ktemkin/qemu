/*
 * Tiny Code Threaded Intepreter for QEMU
 *
 * Copyright (c) 2021 Kate Temkin
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

// Grab our gadget definitions.
// FIXME: use the system path instead of hardcoding this?
#include "aarch64/tcti-gadgets.c.inc"

/* Marker for missing code. */
#define TODO() \
    do { \
        fprintf(stderr, "TODO %s:%u: %s()\n", \
                __FILE__, __LINE__, __func__); \
        tcg_abort(); \
    } while (0)

/* Bitfield n...m (in 32 bit value). */
#define BITS(n, m) (((0xffffffffU << (31 - n)) >> (31 - n + m)) << m)

static TCGConstraintSetIndex tcg_target_op_def(TCGOpcode op)
{
    switch (op) {
    case INDEX_op_ld8u_i32:
    case INDEX_op_ld8s_i32:
    case INDEX_op_ld16u_i32:
    case INDEX_op_ld16s_i32:
    case INDEX_op_ld_i32:
    case INDEX_op_ld8u_i64:
    case INDEX_op_ld8s_i64:
    case INDEX_op_ld16u_i64:
    case INDEX_op_ld16s_i64:
    case INDEX_op_ld32u_i64:
    case INDEX_op_ld32s_i64:
    case INDEX_op_ld_i64:
    case INDEX_op_not_i32:
    case INDEX_op_not_i64:
    case INDEX_op_neg_i32:
    case INDEX_op_neg_i64:
    case INDEX_op_ext8s_i32:
    case INDEX_op_ext8s_i64:
    case INDEX_op_ext16s_i32:
    case INDEX_op_ext16s_i64:
    case INDEX_op_ext8u_i32:
    case INDEX_op_ext8u_i64:
    case INDEX_op_ext16u_i32:
    case INDEX_op_ext16u_i64:
    case INDEX_op_ext32s_i64:
    case INDEX_op_ext32u_i64:
    case INDEX_op_ext_i32_i64:
    case INDEX_op_extu_i32_i64:
    case INDEX_op_bswap16_i32:
    case INDEX_op_bswap16_i64:
    case INDEX_op_bswap32_i32:
    case INDEX_op_bswap32_i64:
    case INDEX_op_bswap64_i64:
        return C_O1_I1(r, r);

    case INDEX_op_st8_i32:
    case INDEX_op_st16_i32:
    case INDEX_op_st_i32:
    case INDEX_op_st8_i64:
    case INDEX_op_st16_i64:
    case INDEX_op_st32_i64:
    case INDEX_op_st_i64:
        return C_O0_I2(r, r);

    case INDEX_op_div_i32:
    case INDEX_op_div_i64:
    case INDEX_op_divu_i32:
    case INDEX_op_divu_i64:
    case INDEX_op_rem_i32:
    case INDEX_op_rem_i64:
    case INDEX_op_remu_i32:
    case INDEX_op_remu_i64:
    case INDEX_op_add_i32:
    case INDEX_op_add_i64:
    case INDEX_op_sub_i32:
    case INDEX_op_sub_i64:
    case INDEX_op_mul_i32:
    case INDEX_op_mul_i64:
    case INDEX_op_and_i32:
    case INDEX_op_and_i64:
    case INDEX_op_andc_i32:
    case INDEX_op_andc_i64:
    case INDEX_op_eqv_i32:
    case INDEX_op_eqv_i64:
    case INDEX_op_nand_i32:
    case INDEX_op_nand_i64:
    case INDEX_op_nor_i32:
    case INDEX_op_nor_i64:
    case INDEX_op_or_i32:
    case INDEX_op_or_i64:
    case INDEX_op_orc_i32:
    case INDEX_op_orc_i64:
    case INDEX_op_xor_i32:
    case INDEX_op_xor_i64:
    case INDEX_op_shl_i32:
    case INDEX_op_shl_i64:
    case INDEX_op_shr_i32:
    case INDEX_op_shr_i64:
    case INDEX_op_sar_i32:
    case INDEX_op_sar_i64:
    case INDEX_op_rotl_i32:
    case INDEX_op_rotl_i64:
    case INDEX_op_rotr_i32:
    case INDEX_op_rotr_i64:
    case INDEX_op_setcond_i32:
    case INDEX_op_setcond_i64:
        return C_O1_I2(r, r, r);

    case INDEX_op_brcond_i32:
    case INDEX_op_brcond_i64:
        return C_O0_I2(r, r);

    case INDEX_op_qemu_ld_i32:
    case INDEX_op_qemu_ld_i64:
        return C_O1_I2(r, r, r);
    case INDEX_op_qemu_st_i32:
    case INDEX_op_qemu_st_i64:
        return C_O0_I3(r, r, r);

    default:
        g_assert_not_reached();
    }
}

static const int tcg_target_reg_alloc_order[] = {
    TCG_REG_R0,
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
    /*
    TCG_REG_R14,  // AREG0
    TCG_REG_R15,  // SP
    */
};

#if MAX_OPC_PARAM_IARGS != 6
# error Fix needed, number of supported input arguments changed!
#endif

static const int tcg_target_call_iarg_regs[] = {
    TCG_REG_R0,
    TCG_REG_R1,
    TCG_REG_R2,
    TCG_REG_R3,
    TCG_REG_R4,
    TCG_REG_R5,
};

static const int tcg_target_call_oarg_regs[] = {
    TCG_REG_R0,
};

#ifdef CONFIG_DEBUG_TCG
static const char *const tcg_target_reg_names[TCG_TARGET_NB_REGS] = {
    "r00",
    "r01",
    "r02",
    "r03",
    "r04",
    "r05",
    "r06",
    "r07",
    "r08",
    "r09",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
};
#endif

static bool patch_reloc(tcg_insn_unit *code_ptr, int type,
                        intptr_t value, intptr_t addend)
{
    /* tcg_out_reloc always uses the same type, addend. */
    tcg_debug_assert(type == sizeof(tcg_target_long));
    tcg_debug_assert(addend == 0);
    tcg_debug_assert(value != 0);
    if (TCG_TARGET_REG_BITS == 32) {
        tcg_patch32(code_ptr, value);
    } else {
        tcg_patch64(code_ptr, value);
    }
    return true;
}

#if defined(CONFIG_DEBUG_TCG_INTERPRETER)
/* Show current bytecode. Used by tcg interpreter. */
void tci_disas(uint8_t opc)
{
    const TCGOpDef *def = &tcg_op_defs[opc];
    fprintf(stderr, "TCG %s %u, %u, %u\n",
            def->name, def->nb_oargs, def->nb_iargs, def->nb_cargs);
}
#endif

/* Write value (native size). */
static void tcg_out_immediate(TCGContext *s, tcg_target_ulong v)
{
    if (TCG_TARGET_REG_BITS == 32) {
        //tcg_out32(s, v);
        tcg_out64(s, v);
    } else {
        tcg_out64(s, v);
    }
}

void tb_target_set_jmp_target(uintptr_t tc_ptr, uintptr_t jmp_rx, uintptr_t jmp_rw, uintptr_t addr)
{
    /* Get a pointer to our immediate, which exists after a single pointer. */
    uintptr_t immediate_addr = jmp_rw;

    /* Patch it to be match our target address. */
    qatomic_set((uint64_t *)immediate_addr, addr);
}


/**
 * TCTI Thunk Helpers
 */

#ifdef CONFIG_SOFTMMU

// TODO: relocate these prototypes?
tcg_target_ulong helper_ret_ldub_mmu_signed(CPUArchState *env, target_ulong addr, TCGMemOpIdx oi, uintptr_t retaddr);
tcg_target_ulong helper_le_lduw_mmu_signed(CPUArchState *env, target_ulong addr, TCGMemOpIdx oi, uintptr_t retaddr);
tcg_target_ulong helper_le_ldul_mmu_signed(CPUArchState *env, target_ulong addr, TCGMemOpIdx oi, uintptr_t retaddr);
tcg_target_ulong helper_be_lduw_mmu_signed(CPUArchState *env, target_ulong addr, TCGMemOpIdx oi, uintptr_t retaddr);
tcg_target_ulong helper_be_ldul_mmu_signed(CPUArchState *env, target_ulong addr, TCGMemOpIdx oi, uintptr_t retaddr);

tcg_target_ulong helper_ret_ldub_mmu_signed(CPUArchState *env, target_ulong addr, TCGMemOpIdx oi, uintptr_t retaddr)
{
    return (int8_t)helper_ret_ldub_mmu(env, addr, oi, retaddr);
}

tcg_target_ulong helper_le_lduw_mmu_signed(CPUArchState *env, target_ulong addr, TCGMemOpIdx oi, uintptr_t retaddr)
{
    return (int16_t)helper_le_lduw_mmu(env, addr, oi, retaddr);
}

tcg_target_ulong helper_le_ldul_mmu_signed(CPUArchState *env, target_ulong addr, TCGMemOpIdx oi, uintptr_t retaddr)
{
    return (int32_t)helper_le_ldul_mmu(env, addr, oi, retaddr);
}

tcg_target_ulong helper_be_lduw_mmu_signed(CPUArchState *env, target_ulong addr, TCGMemOpIdx oi, uintptr_t retaddr)
{
    return (int16_t)helper_be_lduw_mmu(env, addr, oi, retaddr);
}

tcg_target_ulong helper_be_ldul_mmu_signed(CPUArchState *env, target_ulong addr, TCGMemOpIdx oi, uintptr_t retaddr)
{
    return (int32_t)helper_be_ldul_mmu(env, addr, oi, retaddr);
}

#else
#error TCTI currently only supports use of the soft MMU.
#endif


/**
 * TCTI Emmiter Helpers
 */


/* Write gadget pointer. */
static void tcg_out_nullary_gadget(TCGContext *s, void *gadget)
{
    tcg_out_immediate(s, (tcg_target_ulong)gadget);
}

/* Write gadget pointer, plus 64b immediate. */
static void tcg_out_imm64_gadget(TCGContext *s, void *gadget, tcg_target_ulong immediate)
{
    tcg_out_nullary_gadget(s, gadget);
    tcg_out64(s, immediate);
}


/* Write gadget pointer (one register). */
static void tcg_out_unary_gadget(TCGContext *s, void *gadget_base[TCG_TARGET_NB_REGS], unsigned reg0)
{
    tcg_out_nullary_gadget(s, gadget_base[reg0]);
}


/* Write gadget pointer (two registers). */
static void tcg_out_binary_gadget(TCGContext *s, void *gadget_base[TCG_TARGET_NB_REGS][TCG_TARGET_NB_REGS], unsigned reg0, unsigned reg1)
{
    tcg_out_nullary_gadget(s, gadget_base[reg0][reg1]);
}


/* Write gadget pointer (three registers). */
static void tcg_out_ternary_gadget(TCGContext *s, void *gadget_base[TCG_TARGET_NB_REGS][TCG_TARGET_NB_REGS][TCG_TARGET_NB_REGS], unsigned reg0, unsigned reg1, unsigned reg2)

{
    tcg_out_nullary_gadget(s, gadget_base[reg0][reg1][reg2]);
}


/* Write gadget pointer (two registers). */
static void tcg_out_ldst_gadget(TCGContext *s, void * gadget_base[16][16], unsigned reg0, unsigned reg1, uint32_t offset)
{
    int64_t extended_offset = (int32_t)offset;

    tcg_out_binary_gadget(s, gadget_base, reg0, reg1);
    //tcg_out32(s, offset);
    tcg_out64(s, extended_offset);
}


/* Write label. */
static void tcti_out_label(TCGContext *s, TCGLabel *label)
{
    if (label->has_value) {
        tcg_out64(s, label->u.value);
        tcg_debug_assert(label->u.value);
    } else {
        tcg_out_reloc(s, s->code_ptr, sizeof(tcg_target_ulong), label, 0);
        s->code_ptr += sizeof(tcg_target_ulong);
    }
}

/**
 * Generate a register-to-register MOV.
 */
static bool tcg_out_mov(TCGContext *s, TCGType type, TCGReg ret, TCGReg arg)
{
    tcg_debug_assert(ret != arg);

    if (type == TCG_TYPE_I32) {
        tcg_out_binary_gadget(s, gadget_mov_i32, ret, arg);
    } else {
        tcg_out_binary_gadget(s, gadget_mov_i64, ret, arg);
    }


    return true;
}

/**
 * Generate an immediate-to-register MOV.
 */
static void tcg_out_movi(TCGContext *s, TCGType type,
                         TCGReg t0, tcg_target_long arg)
{
    uint32_t arg32 = arg;
    if (type == TCG_TYPE_I32 || arg == arg32) {
        // Emit the mov and its immediate.
        tcg_out_unary_gadget(s, gadget_movi_i32, t0);
        //tcg_out32(s, arg);
        tcg_out64(s, arg);
    } else {
        // Emit the mov and its immediate.
        tcg_out_unary_gadget(s, gadget_movi_i64, t0);
        tcg_out64(s, arg);
    }
}

/**
 * Generate a CALL.
 */
static inline void tcg_out_call(TCGContext *s, const tcg_insn_unit *arg)
{
    tcg_out_nullary_gadget(s, gadget_call);
    tcg_out64(s, (uintptr_t)arg);
}

/**
 * Generates LD instructions.
 */
static void tcg_out_ld(TCGContext *s, TCGType type, TCGReg ret, TCGReg arg1,
                       intptr_t arg2)
{

    if (type == TCG_TYPE_I32) {
        tcg_out_ldst_gadget(s, gadget_ld32u, ret, arg1, arg2); 
    } else {
        tcg_out_ldst_gadget(s, gadget_ld_i64, ret, arg1, arg2); 
    }
}



/**
 * Generate every other operation.
 */
//static void tcg_out_op(TCGContext *s, TCGOpcode opc, const TCGArg *args, const int *const_args)
void tcg_out_op(TCGContext *s, TCGOpcode opc, const TCGArg *args, const int *const_args)
{
    switch (opc) {

    // Exit translation, and return back to QEMU.
    case INDEX_op_exit_tb:
        // Emit a simple gadget with a known return code.
        tcg_out_imm64_gadget(s, gadget_exit_tb, args[0]);
        break;

    // Jump to a translation block.
    case INDEX_op_goto_tb:

        // If we're using a direct jump, we'll emit a "relocation" that can be usd
        // to patch our gadget stream with the target address, later.
        if (s->tb_jmp_insn_offset) {
            // Emit our gadget.
            tcg_out_nullary_gadget(s, gadget_br);

            // Place our current instruction into our "relocation table", so it can
            // be patched once we know where the branch will target...
            s->tb_jmp_insn_offset[args[0]] = tcg_current_code_size(s);

            // ... and emit our relocation.
            tcg_out64(s, args[0]);


        } else {
            /* Indirect jump method. */
            TODO();
        }
        set_jmp_reset_offset(s, args[0]);
        break;

    // Simple branch.
    case INDEX_op_br:
        tcg_out_nullary_gadget(s, gadget_br);
        tcti_out_label(s, arg_label(args[0]));
        break;


    // Set condition flag.
    // a0 = Rd, a1 = Rn, a2 = Rm
    case INDEX_op_setcond_i32:
    {
        void *gadget;

        // We have to emit a different gadget per condition; we'll select which.
        switch(args[3]) {
            case TCG_COND_EQ:  gadget = gadget_setcond_i32_eq; break;
            case TCG_COND_NE:  gadget = gadget_setcond_i32_ne; break;
            case TCG_COND_LT:  gadget = gadget_setcond_i32_lt; break;
            case TCG_COND_GE:  gadget = gadget_setcond_i32_ge; break;
            case TCG_COND_LE:  gadget = gadget_setcond_i32_le; break;
            case TCG_COND_GT:  gadget = gadget_setcond_i32_gt; break;
            case TCG_COND_LTU: gadget = gadget_setcond_i32_lo; break;
            case TCG_COND_GEU: gadget = gadget_setcond_i32_pl; break;
            case TCG_COND_LEU: gadget = gadget_setcond_i32_ls; break;
            case TCG_COND_GTU: gadget = gadget_setcond_i32_hi; break;
            default:
                g_assert_not_reached();
        }

        tcg_out_ternary_gadget(s, gadget, args[0], args[1], args[2]);
        break;
    }

    case INDEX_op_setcond_i64:
    {
        void *gadget;

        // We have to emit a different gadget per condition; we'll select which.
        switch(args[3]) {
            case TCG_COND_EQ:  gadget = gadget_setcond_i64_eq; break;
            case TCG_COND_NE:  gadget = gadget_setcond_i64_ne; break;
            case TCG_COND_LT:  gadget = gadget_setcond_i64_lt; break;
            case TCG_COND_GE:  gadget = gadget_setcond_i64_ge; break;
            case TCG_COND_LE:  gadget = gadget_setcond_i64_le; break;
            case TCG_COND_GT:  gadget = gadget_setcond_i64_gt; break;
            case TCG_COND_LTU: gadget = gadget_setcond_i64_lo; break;
            case TCG_COND_GEU: gadget = gadget_setcond_i64_pl; break;
            case TCG_COND_LEU: gadget = gadget_setcond_i64_ls; break;
            case TCG_COND_GTU: gadget = gadget_setcond_i64_hi; break;
            default:
                g_assert_not_reached();
        }

        tcg_out_ternary_gadget(s, gadget, args[0], args[1], args[2]);
        break;
    }

    /**
     * Load instructions.
     */

    case INDEX_op_ld8u_i32:
    case INDEX_op_ld8u_i64:
        tcg_out_ldst_gadget(s, gadget_ld8u, args[0], args[1], args[2]); 
        break;

    case INDEX_op_ld8s_i32:
    case INDEX_op_ld8s_i64:
        tcg_out_ldst_gadget(s, gadget_ld8s, args[0], args[1], args[2]); 
        break;

    case INDEX_op_ld16u_i32:
    case INDEX_op_ld16u_i64:
        tcg_out_ldst_gadget(s, gadget_ld16u, args[0], args[1], args[2]); 
        break;

    case INDEX_op_ld16s_i32:
    case INDEX_op_ld16s_i64:
        tcg_out_ldst_gadget(s, gadget_ld16s, args[0], args[1], args[2]); 
        break;

    case INDEX_op_ld_i32:
    case INDEX_op_ld32u_i64:
        tcg_out_ldst_gadget(s, gadget_ld32u, args[0], args[1], args[2]); 
        break;

    case INDEX_op_ld_i64:
        tcg_out_ldst_gadget(s, gadget_ld_i64, args[0], args[1], args[2]); 
        break;
    
    case INDEX_op_ld32s_i64:
        tcg_out_ldst_gadget(s, gadget_ld32s_i64, args[0], args[1], args[2]); 
        break;


    /**
     * Store instructions.
     */


    case INDEX_op_st8_i32:
    case INDEX_op_st8_i64:
        tcg_out_ldst_gadget(s, gadget_st8, args[0], args[1], args[2]); 
        break;

    case INDEX_op_st16_i32:
    case INDEX_op_st16_i64:
        tcg_out_ldst_gadget(s, gadget_st16, args[0], args[1], args[2]); 
        break;

    case INDEX_op_st_i32:
    case INDEX_op_st32_i64:
        tcg_out_ldst_gadget(s, gadget_st_i32, args[0], args[1], args[2]); 
        break;

    case INDEX_op_st_i64:
        tcg_out_ldst_gadget(s, gadget_st_i64, args[0], args[1], args[2]); 
        break;

    /**
     * Arithmetic instructions.
     */

    case INDEX_op_add_i32: 
        tcg_out_ternary_gadget(s, gadget_add_i32, args[0], args[1], args[2]); 
        break;

    case INDEX_op_sub_i32:
        tcg_out_ternary_gadget(s, gadget_sub_i32, args[0], args[1], args[2]); 
        break;

    case INDEX_op_mul_i32:
        tcg_out_ternary_gadget(s, gadget_mul_i32, args[0], args[1], args[2]); 
        break;

    case INDEX_op_and_i32:
        tcg_out_ternary_gadget(s, gadget_and_i32, args[0], args[1], args[2]); 
        break;

    // TODO: possibly implement these?
    // Is it worth the extra size? Probably.
    //case INDEX_op_andc_i32:     /* Optional (TCG_TARGET_HAS_andc_i32). */
    //case INDEX_op_eqv_i32:      /* Optional (TCG_TARGET_HAS_eqv_i32). */
    //case INDEX_op_nand_i32:     /* Optional (TCG_TARGET_HAS_nand_i32). */
    //case INDEX_op_nor_i32:      /* Optional (TCG_TARGET_HAS_nor_i32). */
    //case INDEX_op_orc_i32:      /* Optional (TCG_TARGET_HAS_orc_i32). */

    case INDEX_op_or_i32:
        tcg_out_ternary_gadget(s, gadget_or_i32, args[0], args[1], args[2]); 
        break;

    case INDEX_op_xor_i32:
        tcg_out_ternary_gadget(s, gadget_xor_i32, args[0], args[1], args[2]); 
        break;

    case INDEX_op_shl_i32:
        tcg_out_ternary_gadget(s, gadget_shl_i32, args[0], args[1], args[2]); 
        break;

    case INDEX_op_shr_i32:
        tcg_out_ternary_gadget(s, gadget_shr_i32, args[0], args[1], args[2]); 
        break;

    case INDEX_op_sar_i32:
        tcg_out_ternary_gadget(s, gadget_sar_i32, args[0], args[1], args[2]); 
        break;

    case INDEX_op_rotr_i32:     /* Optional (TCG_TARGET_HAS_rot_i32). */
        tcg_out_ternary_gadget(s, gadget_rotr_i32, args[0], args[1], args[2]); 
        break;

    case INDEX_op_rotl_i32:     /* Optional (TCG_TARGET_HAS_rot_i32). */
        tcg_out_ternary_gadget(s, gadget_rotl_i32, args[0], args[1], args[2]); 


    //case INDEX_op_deposit_i32:  /* Optional (TCG_TARGET_HAS_deposit_i32). */

    case INDEX_op_add_i64:
        tcg_out_ternary_gadget(s, gadget_add_i64, args[0], args[1], args[2]); 
        break;

    case INDEX_op_sub_i64:
        tcg_out_ternary_gadget(s, gadget_sub_i64, args[0], args[1], args[2]); 
        break;

    case INDEX_op_mul_i64:
        tcg_out_ternary_gadget(s, gadget_mul_i64, args[0], args[1], args[2]); 
        break;

    case INDEX_op_and_i64:
        tcg_out_ternary_gadget(s, gadget_and_i64, args[0], args[1], args[2]); 
        break;

    //case INDEX_op_andc_i64:     /* Optional (TCG_TARGET_HAS_andc_i64). */
    //case INDEX_op_eqv_i64:      /* Optional (TCG_TARGET_HAS_eqv_i64). */
    //case INDEX_op_nand_i64:     /* Optional (TCG_TARGET_HAS_nand_i64). */
    //case INDEX_op_nor_i64:      /* Optional (TCG_TARGET_HAS_nor_i64). */
    //case INDEX_op_orc_i64:      /* Optional (TCG_TARGET_HAS_orc_i64). */

    case INDEX_op_or_i64:
        tcg_out_ternary_gadget(s, gadget_or_i64, args[0], args[1], args[2]); 
        break;

    case INDEX_op_xor_i64:
        tcg_out_ternary_gadget(s, gadget_xor_i64, args[0], args[1], args[2]); 
        break;

    case INDEX_op_shl_i64:
        tcg_out_ternary_gadget(s, gadget_shl_i64, args[0], args[1], args[2]); 
        break;

    case INDEX_op_shr_i64:
        tcg_out_ternary_gadget(s, gadget_shr_i64, args[0], args[1], args[2]); 
        break;

    case INDEX_op_sar_i64:
        tcg_out_ternary_gadget(s, gadget_sar_i64, args[0], args[1], args[2]); 
        break;

    case INDEX_op_rotl_i64:     /* Optional (TCG_TARGET_HAS_rot_i64). */
        tcg_out_ternary_gadget(s, gadget_rotl_i64, args[0], args[1], args[2]); 
        break;

    case INDEX_op_rotr_i64:     /* Optional (TCG_TARGET_HAS_rot_i64). */
        tcg_out_ternary_gadget(s, gadget_rotr_i64, args[0], args[1], args[2]); 
        break;

    case INDEX_op_div_i64:      /* Optional (TCG_TARGET_HAS_div_i64). */
        tcg_out_ternary_gadget(s, gadget_div_i64, args[0], args[1], args[2]); 
        break;

    case INDEX_op_divu_i64:     /* Optional (TCG_TARGET_HAS_div_i64). */
        tcg_out_ternary_gadget(s, gadget_divu_i64, args[0], args[1], args[2]); 
        break;

    case INDEX_op_rem_i64:      /* Optional (TCG_TARGET_HAS_div_i64). */
        tcg_out_ternary_gadget(s, gadget_rem_i64, args[0], args[1], args[2]); 
        break;

    case INDEX_op_remu_i64:     /* Optional (TCG_TARGET_HAS_div_i64). */
        tcg_out_ternary_gadget(s, gadget_remu_i64, args[0], args[1], args[2]); 
        break;

    //case INDEX_op_deposit_i64:  /* Optional (TCG_TARGET_HAS_deposit_i64). */

    case INDEX_op_brcond_i64:
    {
        void *gadget;

        // We have to emit a different gadget per condition; we'll select which.
        switch(args[2]) {
            case TCG_COND_EQ:  gadget = gadget_brcond_i64_eq; break;
            case TCG_COND_NE:  gadget = gadget_brcond_i64_ne; break;
            case TCG_COND_LT:  gadget = gadget_brcond_i64_lt; break;
            case TCG_COND_GE:  gadget = gadget_brcond_i64_ge; break;
            case TCG_COND_LE:  gadget = gadget_brcond_i64_le; break;
            case TCG_COND_GT:  gadget = gadget_brcond_i64_gt; break;
            case TCG_COND_LTU: gadget = gadget_brcond_i64_lo; break;
            case TCG_COND_GEU: gadget = gadget_brcond_i64_pl; break;
            case TCG_COND_LEU: gadget = gadget_brcond_i64_ls; break;
            case TCG_COND_GTU: gadget = gadget_brcond_i64_hi; break;
            default:
                g_assert_not_reached();
        }

        tcg_out_binary_gadget(s, gadget, args[0], args[1]);

        // Branch target immediate.
        tcti_out_label(s, arg_label(args[3]));

        break;
    }


    case INDEX_op_bswap16_i32:  /* Optional (TCG_TARGET_HAS_bswap16_i32). */
    case INDEX_op_bswap16_i64:  /* Optional (TCG_TARGET_HAS_bswap16_i64). */
        tcg_out_binary_gadget(s, gadget_bswap16, args[0], args[1]);
        break;

    case INDEX_op_bswap32_i32:  /* Optional (TCG_TARGET_HAS_bswap32_i32). */
    case INDEX_op_bswap32_i64:  /* Optional (TCG_TARGET_HAS_bswap32_i64). */
        tcg_out_binary_gadget(s, gadget_bswap32, args[0], args[1]);
        break;

    case INDEX_op_bswap64_i64:  /* Optional (TCG_TARGET_HAS_bswap64_i64). */
        tcg_out_binary_gadget(s, gadget_bswap64, args[0], args[1]);
        break;

    case INDEX_op_not_i64:      /* Optional (TCG_TARGET_HAS_not_i64). */
        tcg_out_binary_gadget(s, gadget_not_i64, args[0], args[1]);
        break;

    case INDEX_op_neg_i64:      /* Optional (TCG_TARGET_HAS_neg_i64). */
        tcg_out_binary_gadget(s, gadget_neg_i64, args[0], args[1]);
        break;

    case INDEX_op_ext8s_i64:    /* Optional (TCG_TARGET_HAS_ext8s_i64). */
        tcg_out_binary_gadget(s, gadget_ext8s_i64, args[0], args[1]);
        break;

    case INDEX_op_ext8u_i32:    /* Optional (TCG_TARGET_HAS_ext8u_i32). */
    case INDEX_op_ext8u_i64:    /* Optional (TCG_TARGET_HAS_ext8u_i64). */
        tcg_out_binary_gadget(s, gadget_ext8u, args[0], args[1]);
        break;

    case INDEX_op_ext16s_i64:   /* Optional (TCG_TARGET_HAS_ext16s_i64). */
        tcg_out_binary_gadget(s, gadget_ext16s_i64, args[0], args[1]);
        break;

    case INDEX_op_ext16u_i32:   /* Optional (TCG_TARGET_HAS_ext16u_i32). */
    case INDEX_op_ext16u_i64:   /* Optional (TCG_TARGET_HAS_ext16u_i64). */
        tcg_out_binary_gadget(s, gadget_ext16u, args[0], args[1]);
        break;

    case INDEX_op_ext32s_i64:   /* Optional (TCG_TARGET_HAS_ext32s_i64). */
    case INDEX_op_ext_i32_i64:
        tcg_out_binary_gadget(s, gadget_ext32s_i64, args[0], args[1]);
        break;

    case INDEX_op_ext32u_i64:   /* Optional (TCG_TARGET_HAS_ext32u_i64). */
    case INDEX_op_extu_i32_i64:
        tcg_out_binary_gadget(s, gadget_ext32u_i64, args[0], args[1]);
        break;

    case INDEX_op_neg_i32:      /* Optional (TCG_TARGET_HAS_neg_i32). */
        tcg_out_binary_gadget(s, gadget_neg_i32, args[0], args[1]);
        break;

    case INDEX_op_not_i32:      /* Optional (TCG_TARGET_HAS_not_i32). */
        tcg_out_binary_gadget(s, gadget_not_i32, args[0], args[1]);
        break;

    case INDEX_op_ext8s_i32:    /* Optional (TCG_TARGET_HAS_ext8s_i32). */
        tcg_out_binary_gadget(s, gadget_ext8s_i32, args[0], args[1]);
        break;

    case INDEX_op_ext16s_i32:   /* Optional (TCG_TARGET_HAS_ext16s_i32). */
        tcg_out_binary_gadget(s, gadget_ext16s_i32, args[0], args[1]);
        break;

    case INDEX_op_div_i32:      /* Optional (TCG_TARGET_HAS_div_i32). */
        tcg_out_ternary_gadget(s, gadget_div_i32, args[0], args[1], args[2]); 
        break;

    case INDEX_op_divu_i32:     /* Optional (TCG_TARGET_HAS_div_i32). */
        tcg_out_ternary_gadget(s, gadget_divu_i32, args[0], args[1], args[2]); 
        break;

    case INDEX_op_rem_i32:      /* Optional (TCG_TARGET_HAS_div_i32). */
        tcg_out_ternary_gadget(s, gadget_rem_i32, args[0], args[1], args[2]); 
        break;

    case INDEX_op_remu_i32:     /* Optional (TCG_TARGET_HAS_div_i32). */
        tcg_out_ternary_gadget(s, gadget_remu_i32, args[0], args[1], args[2]); 
        break;

    case INDEX_op_brcond_i32:
    {
        void *gadget;

        // We have to emit a different gadget per condition; we'll select which.
        switch(args[2]) {
            case TCG_COND_EQ:  gadget = gadget_brcond_i32_eq; break;
            case TCG_COND_NE:  gadget = gadget_brcond_i32_ne; break;
            case TCG_COND_LT:  gadget = gadget_brcond_i32_lt; break;
            case TCG_COND_GE:  gadget = gadget_brcond_i32_ge; break;
            case TCG_COND_LE:  gadget = gadget_brcond_i32_le; break;
            case TCG_COND_GT:  gadget = gadget_brcond_i32_gt; break;
            case TCG_COND_LTU: gadget = gadget_brcond_i32_lo; break;
            case TCG_COND_GEU: gadget = gadget_brcond_i32_pl; break;
            case TCG_COND_LEU: gadget = gadget_brcond_i32_ls; break;
            case TCG_COND_GTU: gadget = gadget_brcond_i32_hi; break;
            default:
                g_assert_not_reached();
        }

        tcg_out_binary_gadget(s, gadget, args[0], args[1]);

        // Branch target immediate.
        tcti_out_label(s, arg_label(args[3]));

        break;
    }

    case INDEX_op_qemu_ld_i32:
    {
        void *gadget;

        // We have to emit a different gadget per helper. Figure out which one
        switch (get_memop(args[2]) & (MO_BSWAP | MO_SSIZE)) {
            case MO_UB:   gadget = gadget_qemu_ld_ub_i32;   break;
            case MO_SB:   gadget = gadget_qemu_ld_sb_i32;   break;
            case MO_LEUW: gadget = gadget_qemu_ld_leuw_i32; break;
            case MO_LESW: gadget = gadget_qemu_ld_lesw_i32; break;
            case MO_LEUL: gadget = gadget_qemu_ld_leul_i32; break;
            case MO_LESL: gadget = gadget_qemu_ld_lesl_i32; break;
            case MO_LEQ:  gadget = gadget_qemu_ld_leq_i32;  break;
            case MO_BEUW: gadget = gadget_qemu_ld_beuw_i32; break;
            case MO_BESW: gadget = gadget_qemu_ld_besw_i32; break;
            case MO_BEUL: gadget = gadget_qemu_ld_beul_i32; break;
            case MO_BESL: gadget = gadget_qemu_ld_besl_i32; break;
            case MO_BEQ:  gadget = gadget_qemu_ld_beq_i32;  break;
            default:
                g_assert_not_reached();
        }

        // Args:
        // - our gadget encodes the addres register and destination register
        // - an immediate32 encodes our operation index 
        tcg_out_binary_gadget(s, gadget, args[0], args[1]);
        tcg_out64(s, args[2]); // TODO: fix encoding to be 4b
        break;
    }

    case INDEX_op_qemu_ld_i64:
    {
        void *gadget;

        // We have to emit a different gadget per helper. Figure out which one
        switch (get_memop(args[2]) & (MO_BSWAP | MO_SSIZE)) {
            case MO_UB:   gadget = gadget_qemu_ld_ub_i64;   break;
            case MO_SB:   gadget = gadget_qemu_ld_sb_i64;   break;
            case MO_LEUW: gadget = gadget_qemu_ld_leuw_i64; break;
            case MO_LESW: gadget = gadget_qemu_ld_lesw_i64; break;
            case MO_LEUL: gadget = gadget_qemu_ld_leul_i64; break;
            case MO_LESL: gadget = gadget_qemu_ld_lesl_i64; break;
            case MO_LEQ:  gadget = gadget_qemu_ld_leq_i64;  break;
            case MO_BEUW: gadget = gadget_qemu_ld_beuw_i64; break;
            case MO_BESW: gadget = gadget_qemu_ld_besw_i64; break;
            case MO_BEUL: gadget = gadget_qemu_ld_beul_i64; break;
            case MO_BESL: gadget = gadget_qemu_ld_besl_i64; break;
            case MO_BEQ:  gadget = gadget_qemu_ld_beq_i64;  break;
            default:
                g_assert_not_reached();
        }

        // Args:
        // - an immediate32 encodes our operation index 
        tcg_out_binary_gadget(s, gadget, args[0], args[1]);
        tcg_out64(s, args[2]); // TODO: fix encoding to be 4b
        break;
    }

    case INDEX_op_qemu_st_i32:
    {
        void *gadget;

        // We have to emit a different gadget per helper. Figure out which one
        switch (get_memop(args[2]) & (MO_BSWAP | MO_SSIZE)) {
            case MO_UB:   gadget = gadget_qemu_st_ub_i32;   break;
            case MO_LEUW: gadget = gadget_qemu_st_leuw_i32; break;
            case MO_LEUL: gadget = gadget_qemu_st_leul_i32; break;
            case MO_LEQ:  gadget = gadget_qemu_st_leq_i32;  break;
            case MO_BEUW: gadget = gadget_qemu_st_beuw_i32; break;
            case MO_BEUL: gadget = gadget_qemu_st_beul_i32; break;
            case MO_BEQ:  gadget = gadget_qemu_st_beq_i32;  break;
            default:
                g_assert_not_reached();
        }

        // Args:
        // - our gadget encodes the target and address registers
        // - an immediate32 encodes our operation index 
        tcg_out_binary_gadget(s, gadget, args[0], args[1]);
        tcg_out64(s, args[2]); // FIXME: double encoded
        break;
    }

    case INDEX_op_qemu_st_i64:
    {
        void *gadget;

        // We have to emit a different gadget per helper. Figure out which one
        switch (get_memop(args[2]) & (MO_BSWAP | MO_SSIZE)) {
            case MO_UB:   gadget = gadget_qemu_st_ub_i64;   break;
            case MO_LEUW: gadget = gadget_qemu_st_leuw_i64; break;
            case MO_LEUL: gadget = gadget_qemu_st_leul_i64; break;
            case MO_LEQ:  gadget = gadget_qemu_st_leq_i64;  break;
            case MO_BEUW: gadget = gadget_qemu_st_beuw_i64; break;
            case MO_BEUL: gadget = gadget_qemu_st_beul_i64; break;
            case MO_BEQ:  gadget = gadget_qemu_st_beq_i64;  break;
            default:
                g_assert_not_reached();
        }

        // Args:
        // - our gadget encodes the target and address registers
        // - an immediate32 encodes our operation index 
        tcg_out_binary_gadget(s, gadget, args[0], args[1]);
        tcg_out64(s, args[2]); // FIXME: double encoded
        break;
    }



    // Memory barriers.
    case INDEX_op_mb:
    {
        static void* sync[] = {
            [0 ... TCG_MO_ALL]            = gadget_mb_all,
            [TCG_MO_ST_ST]                = gadget_mb_st,
            [TCG_MO_LD_LD]                = gadget_mb_ld,
            [TCG_MO_LD_ST]                = gadget_mb_ld,
            [TCG_MO_LD_ST | TCG_MO_LD_LD] = gadget_mb_ld,
        };
        tcg_out_nullary_gadget(s, sync[args[0] & TCG_MO_ALL]);
        break;
    }

    case INDEX_op_mov_i32:  /* Always emitted via tcg_out_mov.  */
    case INDEX_op_mov_i64:
    case INDEX_op_call:     /* Always emitted via tcg_out_call.  */
    default:
        tcg_abort();
    }
}

/**
 * Generate immediate stores.
 */
static void tcg_out_st(TCGContext *s, TCGType type, TCGReg arg, TCGReg arg1,
                       intptr_t arg2)
{
    if (type == TCG_TYPE_I32) {
        tcg_out_binary_gadget(s, gadget_st_i32, arg, arg1);
        //tcg_out32(s, arg2);
        tcg_out64(s, arg2);
    } else {
        tcg_out_binary_gadget(s, gadget_st_i64, arg, arg1);
        //tcg_out32(s, arg2);
        tcg_out64(s, arg2);
    }
}

static inline bool tcg_out_sti(TCGContext *s, TCGType type, TCGArg val,
                               TCGReg base, intptr_t ofs)
{
    return false;
}

/* Test if a constant matches the constraint. */
static int tcg_target_const_match(tcg_target_long val, TCGType type,
                                  const TCGArgConstraint *arg_ct)
{
    /* No need to return 0 or 1, 0 or != 0 is good enough. */
    return arg_ct->ct & TCG_CT_CONST;
}

static void tcg_target_init(TCGContext *s)
{
#if defined(CONFIG_DEBUG_TCG_INTERPRETER)
    const char *envval = getenv("DEBUG_TCG");
    if (envval) {
        qemu_set_log(strtol(envval, NULL, 0));
    }
#endif

    /* The current code uses uint8_t for tcg operations. */
    tcg_debug_assert(tcg_op_defs_max <= UINT8_MAX);

    /* Registers available for 32 bit operations. */
    tcg_target_available_regs[TCG_TYPE_I32] = BIT(TCG_TARGET_NB_REGS) - 1;
    /* Registers available for 64 bit operations. */
    tcg_target_available_regs[TCG_TYPE_I64] = BIT(TCG_TARGET_NB_REGS) - 1;
    /* TODO: Which registers should be set here? */
    tcg_target_call_clobber_regs = BIT(TCG_TARGET_NB_REGS) - 1;

    s->reserved_regs = 0;
    tcg_regset_set_reg(s->reserved_regs, TCG_REG_CALL_STACK);
    

    /* We use negative offsets from "sp" so that we can distinguish
       stores that might pretend to be call arguments.  */
    tcg_set_frame(s, TCG_REG_CALL_STACK, -CPU_TEMP_BUF_NLONGS * sizeof(long), CPU_TEMP_BUF_NLONGS * sizeof(long));
}

/* Generate global QEMU prologue and epilogue code. */
static inline void tcg_target_qemu_prologue(TCGContext *s)
{
    // No prologue; as we're interpreted.
}
