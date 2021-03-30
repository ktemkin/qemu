/*
 * Tiny Code Threaded Interpreter for QEMU
 *
 * Copyright (c) 2021 Kate Temkin <k@ktemkin.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "tcg/tcg.h"           /* MAX_OPC_PARAM_IARGS */
#include "exec/cpu_ldst.h"
#include "tcg/tcg-op.h"
#include "qemu/compiler.h"

/* Enable TCTI assertions only when debugging TCG (and without NDEBUG defined).
 * Without assertions, the interpreter runs much faster. */
#if defined(CONFIG_DEBUG_TCG)
# define tcti_assert(cond) assert(cond)
#else
# define tcti_assert(cond) ((void)0)
#endif


void tcti_instrumentation(void *addr, void *next);
void tcti_instrumentation(void *addr, void *next)
{
    fprintf(stderr, "IP: %p, next gadget: %p\n", addr - 8, next);
    fflush(stderr);
}

void tcti_pre_instrumentation(void);
__attribute__((naked)) void tcti_pre_instrumentation(void)
{
  asm(
    // Store our machine state.
    "\nstp x28, lr, [sp, #-16]!"
    "\nstp x15, x16, [sp, #-16]!"
    "\nstp x13, x14, [sp, #-16]!"
    "\nstp x11, x12, [sp, #-16]!"
    "\nstp x9,  x10, [sp, #-16]!"
    "\nstp x7,  x8, [sp, #-16]!"
    "\nstp x5,  x6, [sp, #-16]!"
    "\nstp x3,  x4, [sp, #-16]!"
    "\nstp x1,  x2, [sp, #-16]!"
    "\nstr x0,      [sp, #-16]!"

    // Call our instrumentation function.
    "\nmov x0, x28"
    "\nmov x1, x27"
    "\nbl _tcti_instrumentation"
    
    // Restore our machine state.
    "\nldr x0,      [sp], #16"
    "\nldp x1,  x2, [sp], #16"
    "\nldp x3,  x4, [sp], #16"
    "\nldp x5,  x6, [sp], #16"
    "\nldp x7,  x8, [sp], #16"
    "\nldp x9,  x10, [sp], #16"
    "\nldp x11, x12, [sp], #16"
    "\nldp x13, x14, [sp], #16"
    "\nldp x15, x16, [sp], #16"
    "\nldp x28, lr, [sp], #16"

    //Jump to the next gadget.
    "\nbr x27"
  );
}


/* Dispatch the bytecode stream contained in our translation buffer. */
uintptr_t QEMU_DISABLE_CFI tcg_qemu_tb_exec(CPUArchState *env, const void *v_tb_ptr)
{
    // Create our per-CPU temporary storage.
    long tcg_temps[CPU_TEMP_BUF_NLONGS];

    uintptr_t final_tb_ptr = 0;
    uintptr_t sp_value = (uintptr_t)(tcg_temps + CPU_TEMP_BUF_NLONGS);

    // Ensure our target configuration hasn't changed.
    tcti_assert(TCG_AREG0 == TCG_REG_R14);
    tcti_assert(TCG_REG_CALL_STACK == TCG_REG_R15);

    asm(
        // Our threaded-dispatch prologue needs to set up things for our machine to run.
        // This means:
        //   - Set up TCG_AREG0 (R14) to point to our architectural state.
        //   - Set up TCG_REG_CALL_STACK (R15) to point to our temporary buffer.
        //   - Point x28 (our bytecode "instruction pointer") to the relevant stream address.
        "ldr x14, %[areg0]\n"
        "ldr x15, %[sp_value]\n"
        "ldr x28, %[start_tb_ptr]\n"

        // To start our code, we'll -call- the gadget at the first bytecode pointer.
        // Note that we call/branch-with-link, here; so our TB_EXIT gadget can RET in order
        // to return to this point when things are complete.
        "ldr x27, [x28], #8\n"
        "blr x27\n"

        // Finally, we'll copy out our final TB value.
        "str x28, %[end_tb_ptr]\n"

        : [end_tb_ptr]   "=m" (final_tb_ptr)

        : [areg0]        "m"  (env), 
          [sp_value]     "m"  (sp_value), 
          [start_tb_ptr] "m"  (v_tb_ptr)

        // We touch _every_ one of the lower registers, as we use these to execute directly.
        : "x0", "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",
          "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",

        // We also use x27 for our temporary value, and x28 as our bytecode poitner.
        "x27", "x28"
    );

    return final_tb_ptr;
}