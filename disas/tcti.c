/*
 * Tiny Code Interpreter for QEMU - disassembler
 *
 * Copyright (c) 2011 Stefan Weil
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
#include "disas/dis-asm.h"
#include "tcg/tcg.h"

#include <dlfcn.h>


/* Disassemble TCI bytecode. */
int print_insn_tcti(bfd_vma addr, disassemble_info *info)
{
    Dl_info symbol_info = {};
    char symbol_name[33];

    int status;
    uint64_t block;

    // Read the relevant pointer.
    status = info->read_memory_func(addr, (void *)&block, sizeof(block), info);
    if (status != 0) {
        info->memory_error_func(status, addr, info);
        return -1;
    }

    // Most of our disassembly stream will be gadgets. Try to get their names, for nice output.
    dladdr((void *)block, &symbol_info);

    if(symbol_info.dli_sname != 0) {
        strlcpy(symbol_name, symbol_info.dli_sname, 32);
        info->fprintf_func(info->stream, "%s (%016llx)", symbol_name, block);
    } else {
        info->fprintf_func(info->stream, "%016llx", block);
    }

    return sizeof(block);
}
