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

// DEBUG ONLY
#include <dlfcn.h>

/* Enable TCTI assertions only when debugging TCG (and without NDEBUG defined).
 * Without assertions, the interpreter runs much faster. */
#if defined(CONFIG_DEBUG_TCG)
# define tcti_assert(cond) assert(cond)
#else
# define tcti_assert(cond) ((void)0)
#endif

struct guest_state {
    uint64_t pc;
    uint64_t lr;
    uint64_t x[16];
}
__attribute__((packed));


void tcti_instrumentation(struct guest_state *s);
void tcti_instrumentation(struct guest_state *s) {
    Dl_info symbol_info = {};
    char symbol_name[33] = { 0 };

    // Find our gadget's name.
    void **tbp = (void *)(s->pc - 8);    

    dladdr(*tbp, &symbol_info);
    if (symbol_info.dli_sname)
        strlcpy(symbol_name, symbol_info.dli_sname, 32);

    // Get our architecture state, so we can print out the guest PC.
    CPUArchState *env = (void *)s->x[14];

    //offset testing
    uintptr_t env_ptr = ((uintptr_t)env) + 0x40;
    uint64_t *touch_loc = (void *)env_ptr;

    fprintf(stderr, "x0:  %16llx    x1:  %16llx      x2: %16llx     x3: %16llx\n", s->x[ 0],  s->x[ 1],  s->x[ 2], s->x[ 3]);
    fprintf(stderr, "x4:  %16llx    x5:  %16llx      x6: %16llx     x7: %16llx\n", s->x[ 4],  s->x[ 5],  s->x[ 6], s->x[ 7]);
    fprintf(stderr, "x8:  %16llx    x9:  %16llx     x10: %16llx    x11: %16llx\n", s->x[ 8],  s->x[ 9],  s->x[10], s->x[11]);
    fprintf(stderr, "x12: %16llx    x13: %16llx     x14: %16llx    x15: %16llx\n", s->x[12],  s->x[13],  s->x[14], s->x[15]);
    fprintf(stderr, "gpc: %16llx    glr: %16llx     gsp: %16llx  e[40]: %16llx\n", env->pc, env->xregs[30], env->xregs[31], *touch_loc);
    fprintf(stderr, "----NEXT: %p [%s(%p, %p)] ------\n", tbp, symbol_name, tbp[1], tbp[2]);
}

void tcti_pre_instrumentation(void);
__attribute__((naked)) void tcti_pre_instrumentation(void)
{
  asm(
    // Store our machine state.
    "\nstp x14, x15, [sp, #-16]!"
    "\nstp x12, x13, [sp, #-16]!"
    "\nstp x10, x11, [sp, #-16]!"
    "\nstp x8,  x9,  [sp, #-16]!"
    "\nstp x6,  x7,  [sp, #-16]!"
    "\nstp x4,  x5,  [sp, #-16]!"
    "\nstp x2,  x3,  [sp, #-16]!"
    "\nstp x0,  x1,  [sp, #-16]!"
    "\nstp x28, lr,  [sp, #-16]!"

    // Call our instrumentation function.
    "\nmov x0, sp"
    "\nbl _tcti_instrumentation"
    
    // Restore our machine state.
    "\nldp x28, lr, [sp], #16"
    "\nldp x0,  x1, [sp], #16"
    "\nldp x2,  x3, [sp], #16"
    "\nldp x4,  x5, [sp], #16"
    "\nldp x6,  x7, [sp], #16"
    "\nldp x8,  x9, [sp], #16"
    "\nldp x10, x11, [sp], #16"
    "\nldp x12, x13, [sp], #16"
    "\nldp x14, x15, [sp], #16"

    //Jump to the next gadget.
    "\nbr x27"
  );
}


/* Dispatch the bytecode stream contained in our translation buffer. */
uintptr_t QEMU_DISABLE_CFI tcg_qemu_tb_exec(CPUArchState *env, const void *v_tb_ptr)
{
    // Create our per-CPU temporary storage.
    long tcg_temps[CPU_TEMP_BUF_NLONGS];

    uint64_t return_value = 0;
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

        // Finally, we'll copy out our final return value.
        "str x0, %[return_value]\n"

        : [return_value] "=m" (return_value)

        : [areg0]        "m"  (env), 
          [sp_value]     "m"  (sp_value), 
          [start_tb_ptr] "m"  (v_tb_ptr)

        // We touch _every_ one of the lower registers, as we use these to execute directly.
        : "x0", "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",
          "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",

        // We also use x26/x27 for temporary values, and x28 as our bytecode poitner.
          "x26", "x27", "x28", "cc", "memory"
    );

    return return_value;
}
