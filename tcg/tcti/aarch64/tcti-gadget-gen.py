""" Gadget-code generator for QEMU TCTI on AArch64. 

Generates a C-code include file containing 'gadgets' for use by TCTI.
"""

import sys
import itertools

# Epilogue code follows at the end of each gadget, and handles continuing execution.
EPILOGUE = ( 
    # Load our next gadget address from our bytecode stream, advancing it.
    "ldr x27, [x28], #8",

    # Jump to the next gadget.
    "br x27"
)

# The number of general-purpose registers we're affording the TCG. This must match
# the configuration in the TCTI target.
TCG_REGISTER_COUNT   = 16
TCG_REGISTER_NUMBERS = list(range(TCG_REGISTER_COUNT))

# Helper that provides each of the AArch64 condition codes of interest.
ARCH_CONDITION_CODES = ["eq", "ne", "lt", "ge", "le", "gt", "lo", "hs", "ls", "hi"]

# Statistics.
gadgets      = 0
instructions = 0

def simple(name, *lines):
    """ Generates a simple gadget that needs no per-register specialization. """

    global gadgets, instructions

    gadgets += 1

    # Create our C/ASM framing.
    #print(f"__attribute__((naked)) static void gadget_{name}(void)")
    print(f"__attribute__((naked)) void gadget_{name}(void);")
    print(f"__attribute__((naked)) void gadget_{name}(void)")
    print("{")

    # Add the core gadget
    print("\tasm(")
    for line in lines + EPILOGUE:
        print(f"\t\t\"{line} \\n\"")
        instructions += 1
    print("\t);")

    # End our framing.
    print("}\n")


def with_register_substitutions(name, substitutions, *lines, immediate_range=range(0)):
    """ Generates a collection of gadgtes with register substitutions. """

    def substitutions_for_letter(letter, number, line):
        """ Helper that transforms Wd => w1, implementing gadget substitutions. """

        # Register substitutions...
        line = line.replace(f"X{letter}", f"x{number}")
        line = line.replace(f"W{letter}", f"w{number}")

        # ... immediate substitutions.
        line = line.replace(f"I{letter}", f"{number}")
        return line

        
    # Build a list of all the various stages we'll iterate over...
    immediate_parameters = list(immediate_range)
    parameters   = ([TCG_REGISTER_NUMBERS] * len(substitutions))

    # ... adding immediates, if need be.
    if immediate_parameters:
        parameters.append(immediate_parameters)
        substitutions = substitutions + ['i']

    # Generate a list of register-combinations we'll support.
    permutations = itertools.product(*parameters)

    #  For each permutation...
    for permutation in permutations:
        new_lines = lines

        # Replace each placeholder element with its proper value...
        for index, element in enumerate(permutation):
            letter = substitutions[index]
            number = element

            # Create new gadgets for the releavnt line...
            new_lines = [substitutions_for_letter(letter, number, line) for line in new_lines]

        # ... and emit the gadget.
        permutation_id = "_arg".join(str(number) for number in permutation)
        simple(f"{name}_arg{permutation_id}", *new_lines)


def with_dnm(name, *lines):
    """ Generates a collection of gadgets with substitutions for Xd, Xn, and Xm, and equivalents. """
    with_register_substitutions(name, ("d", "n", "m"), *lines)

    # Print out an array that contains all of our gadgets, for lookup.
    print(f"void* gadget_{name}[{TCG_REGISTER_COUNT}][{TCG_REGISTER_COUNT}][{TCG_REGISTER_COUNT}] = ", end="")
    print("{")

    # D array
    for d in TCG_REGISTER_NUMBERS:
        print("\t{")

        # N array
        for n in TCG_REGISTER_NUMBERS:
            print("\t\t{", end="")

            # M array
            for m in TCG_REGISTER_NUMBERS:
                print(f"gadget_{name}_arg{d}_arg{n}_arg{m}", end=", ")

            print("},")
        print("\t},")
    print("};")


def with_dn_immediate(name, *lines, immediate_range):
    """ Generates a collection of gadgets with substitutions for Xd, Xn, and Xm, and equivalents. """
    with_register_substitutions(name, ["d", "n"], *lines, immediate_range=immediate_range)

    # Print out an array that contains all of our gadgets, for lookup.
    print(f"void* gadget_{name}[{TCG_REGISTER_COUNT}][{TCG_REGISTER_COUNT}][{len(immediate_range)}] = ", end="")
    print("{")

    # D array
    for d in TCG_REGISTER_NUMBERS:
        print("\t{")

        # N array
        for n in TCG_REGISTER_NUMBERS:
            print("\t\t{", end="")

            # M array
            for i in immediate_range:
                print(f"gadget_{name}_arg{d}_arg{n}_arg{i}", end=", ")

            print("},")
        print("\t},")
    print("};")


def with_pair(name, substitutions, *lines):
    """ Generates a collection of gadgets with two subtstitutions."""
    with_register_substitutions(name, substitutions, *lines)

    # Print out an array that contains all of our gadgets, for lookup.
    print(f"void* gadget_{name}[{TCG_REGISTER_COUNT}][{TCG_REGISTER_COUNT}] = ", end="")
    print("{")

    # N array
    for a in TCG_REGISTER_NUMBERS:
        print("\t\t{", end="")

        # M array
        for b in TCG_REGISTER_NUMBERS:
            print(f"gadget_{name}_arg{a}_arg{b}", end=", ")

        print("},")
    print("};")


def math_dnm(name, mnemonic):
    """ Equivalent to `with_dnm`, but creates a _i32 and _i64 variant. For simple math. """
    with_dnm(f'{name}_i32', f"{mnemonic} Wd, Wn, Wm")
    with_dnm(f'{name}_i64', f"{mnemonic} Xd, Xn, Xm")

def math_dn(name, mnemonic):
    """ Equivalent to `with_dn`, but creates a _i32 and _i64 variant. For simple math. """
    with_dn(f'{name}_i32', f"{mnemonic} Wd, Wn")
    with_dn(f'{name}_i64', f"{mnemonic} Xd, Xn")


def with_nm(name, *lines):
    """ Generates a collection of gadgets with substitutions for Xn, and Xm, and equivalents. """
    with_pair(name, ('n', 'm',), *lines)


def with_dn(name, *lines):
    """ Generates a collection of gadgets with substitutions for Xd, and Xn, and equivalents. """
    with_pair(name, ('d', 'n',), *lines)


def ldst_dn(name, *lines):
    """ Generates a collection of gadgets with substitutions for Xd, and Xn, and equivalents. 
    
    This variant is optimized for loads and stores, and optimizes common offset cases.
    """

    #
    # Simple case: create our gadgets.
    #
    with_dn(name, "ldr x27, [x28], #8", *lines) # FIXME: encode as 4B, not 8B

    #
    # Optimization case: create variants of our gadgets with our offsets replaced with common immediates.
    #
    immediate_lines_pos = [line.replace("x27", "#Ii") for line in lines]
    with_dn_immediate(f"{name}_imm", *immediate_lines_pos, immediate_range=range(64))

    immediate_lines_aligned = [line.replace("x27", "#(Ii << 3)") for line in lines]
    with_dn_immediate(f"{name}_sh8_imm", *immediate_lines_aligned, immediate_range=range(64))

    immediate_lines_neg = [line.replace("x27", "#-Ii") for line in lines]
    with_dn_immediate(f"{name}_neg_imm", *immediate_lines_neg, immediate_range=range(64))



def with_single(name, substitution, *lines):
    """ Generates a collection of gadgets with two subtstitutions."""
    with_register_substitutions(name, (substitution,), *lines)

    # Print out an array that contains all of our gadgets, for lookup.
    print(f"void* gadget_{name}[{TCG_REGISTER_COUNT}] = ", end="")
    print("{")

    for n in TCG_REGISTER_NUMBERS:
        print(f"gadget_{name}_arg{n}", end=", ")

    print("};")


def with_d_immediate(name, *lines, immediate_range=range(0)):
    """ Generates a collection of gadgets with two subtstitutions."""
    with_register_substitutions(name, ['d'], *lines, immediate_range=immediate_range)

    # Print out an array that contains all of our gadgets, for lookup.
    print(f"void* gadget_{name}[{TCG_REGISTER_COUNT}][{len(immediate_range)}] = ", end="")
    print("{")

    # D array
    for a in TCG_REGISTER_NUMBERS:
        print("\t\t{", end="")

        # I array
        for b in immediate_range:
            print(f"gadget_{name}_arg{a}_arg{b}", end=", ")

        print("},")
    print("};")



def with_d(name, *lines):
    """ Generates a collection of gadgets with substitutions for Xd. """
    with_single(name, 'd', *lines)


# Assembly code for saving our machine state before entering the C runtime.
C_CALL_PROLOGUE = [
    # Store our machine state.
    "str x25,      [sp, #-16]!",
    "stp x14, x15, [sp, #-16]!",
    "stp x12, x13, [sp, #-16]!",
    "stp x10, x11, [sp, #-16]!",
    "stp x8,  x9,  [sp, #-16]!",
    "stp x6,  x7,  [sp, #-16]!",
    "stp x4,  x5,  [sp, #-16]!",
    "stp x2,  x3,  [sp, #-16]!",
    "stp x0,  x1,  [sp, #-16]!",
    "stp x28, lr,  [sp, #-16]!",
]

# Assembly code for restoring our machine state after leaving the C runtime.
C_CALL_EPILOGUE = [
    "ldp x28, lr, [sp], #16",
    "ldp x0,  x1, [sp], #16",
    "ldp x2,  x3, [sp], #16",
    "ldp x4,  x5, [sp], #16",
    "ldp x6,  x7, [sp], #16",
    "ldp x8,  x9, [sp], #16",
    "ldp x10, x11, [sp], #16",
    "ldp x12, x13, [sp], #16",
    "ldp x14, x15, [sp], #16",
    "ldr x25,      [sp], #16",
]


def with_thunk_d(name, *lines, postscript=()):
    """ Create a thunk into our C runtime for an Rd-substituion operation. """

    with_d(name,
        *C_CALL_PROLOGUE,
        *lines,
        *C_CALL_EPILOGUE,
        *postscript
    )

def with_thunk_dn(name, *lines, postscript=()):
    """ Create a thunk into our C runtime for an Rd/Rn-substituion operation. """
    with_dn(name,
        *C_CALL_PROLOGUE,
        *lines,
        *C_CALL_EPILOGUE,
        *postscript
    )


def ld_thunk(name, c_function_name):
    """ Creates a thunk into our C runtime for a QEMU ST operation. """

    # Build our thunk...
    thunk = [
        # Per our calling convention:
        #6 - Move our architectural environment into x0, from x14.
        # - Move our target address into x1. [Placed in x27 below.]
        # - Move our operation info into x2, from an immediate32.
        # - Move the next bytecode pointer into x3, from x28.
        "mov   x0, x14",
        "mov   x1, x27",
        "ldr   x2, [x28], #8", # FIXME: encode as 4, not 8
        "mov   x3, x28",

        # Perform our actual core code.
        f"bl {c_function_name}",

        # Temporarily store our result in a register that won't get trashed.
        "mov x27, x0",
    ]   

    # ... and instantiate it in 32 and 64 bit versions.
    with_thunk_dn(f"{name}_i32", "mov x27, Xn", *thunk, postscript=("add x28, x28, #8", "mov Wd, w27"))
    with_thunk_dn(f"{name}_i64", "mov x27, Xn", *thunk, postscript=("add x28, x28, #8", "mov Xd, x27"))


def st_thunk(name, c_function_name):
    """ Creates a thunk into our C runtime for a QEMU ST operation. """

    # Build our thunk...
    thunk = [
        # Per our calling convention:
        # - Move our architectural environment into x0, from x14.
        # - Move our target address into x1. [Moved into x26 below].
        # - Move our target value into x2. [Moved into x27 below].
        # - Move our operation info into x3, from an immediate32.
        # - Move the next bytecode pointer into x4, from x28.
        "mov   x0, x14",
        "mov   x1, x26",
        "mov   x2, x27",
        "ldr   x3, [x28], #8", # FIXME: encode as 4, not 8
        "mov   x4, x28",

        # Perform our actual core code.
        f"bl {c_function_name}",
    ]   

    # Post-script: re-consume our immediates.
    ps = ("add x28, x28, #8",)

    # ... and instantiate it in 32 and 64 bit versions.
    with_thunk_dn(f"{name}_i32", "mov x27, Xd", "mov w26, Wn", *thunk, postscript=ps)
    with_thunk_dn(f"{name}_i64", "mov x27, Xd", "mov x26, Xn", *thunk, postscript=ps)


#
# Gadget definitions.
#

print("/* Automatically generated by tcti-gadget-gen.py. Do not edit. */\n")

# Call a C language helper function by address.
simple("call",
    # Get our C runtime function's location as a pointer-sized immediate...
    "ldr x27, [x28], #8",

    # Store our TB return address for our helper.
    "str x28, [x25]",

    # Prepare ourselves to call into our C runtime...
    *C_CALL_PROLOGUE,

    # ... perform the call itself ...
    "blr x27",

    # Save the result of our call for later.
    "mov x27, x0",

    # ... and restore our environment.
    *C_CALL_EPILOGUE,

    # Restore our return value.
    "mov x0, x27"
)

# Branch to a given immediate address.
simple("br",
    # Use our immediate argument as our new bytecode-pointer location.
    "ldr x28, [x28]"
)

# Exit from a translation buffer execution.
simple("exit_tb",

    # We have a single immediate argument, which contains our return code.
    # Place it into x0, as one would a return code.
    "ldr x0, [x28], #8",

    # And finally, return back to the code that invoked our gadget stream.
    "ret"
)


for condition in ARCH_CONDITION_CODES:

    # Performs a comparison between two operands.
    with_dnm(f"setcond_i32_{condition}",
        "subs Wd, Wn, Wm",
        f"cset Wd, {condition}"
    )
    with_dnm(f"setcond_i64_{condition}",
        "subs Xd, Xn, Xm",
        f"cset Xd, {condition}"
    )

    # Branches iff a given comparison is true.
    with_nm(f'brcond_i32_{condition}',

        # Grab our immediate argument.
        "ldr x27, [x28], #8",

        # Perform our comparison and conditional branch.
        "subs Wzr, Wn, Wm",
        f"b{condition} 1f",

        "0:", # not taken
           # Perform our end-of-instruction epilogue.
            *EPILOGUE,

        "1:" # taken
            # Update our bytecode pointer to take the label.
            "mov x28, x27"
    )


    # Branches iff a given comparison is true.
    with_nm(f'brcond_i64_{condition}',

        # Grab our immediate argument.
        "ldr x27, [x28], #8",

        # Perform our comparison and conditional branch.
        "subs Xzr, Xn, Xm",
        f"b{condition} 1f",

        "0:", # not taken
            # Perform our end-of-instruction epilogue.
            *EPILOGUE,

        "1:" # taken
            # Update our bytecode pointer to take the label.
            "mov x28, x27"
    )


# MOV variants.
with_dn("mov_i32",     "mov Wd, Wn")
with_dn("mov_i64",     "mov Xd, Xn")
with_d("movi_i32", "ldr Wd, [x28], #8")   # FIXME: encode as 4, not 8
with_d("movi_i64", "ldr Xd, [x28], #8")

# Create MOV variants that have common constants built in to the gadget.
# This optimization helps costly reads from memories for simple operations.
with_d_immediate("movi_imm_i32", "mov Wd, #Ii", immediate_range=range(64))
with_d_immediate("movi_imm_i64", "mov Xd, #Ii", immediate_range=range(64))

# LOAD variants.
ldst_dn("ld8u",      "ldrb  Wd, [Xn, x27]")
ldst_dn("ld8s",      "ldrsb Wd, [Xn, x27]")
ldst_dn("ld16u",     "ldrh  Wd, [Xn, x27]")
ldst_dn("ld16s",     "ldrsh Wd, [Xn, x27]")
ldst_dn("ld32u",     "ldr   Wd, [Xn, x27]")
ldst_dn("ld32s_i64", "ldrsw Xd, [Xn, x27]")
ldst_dn("ld_i64",    "ldr   Xd, [Xn, x27]")

# STORE variants.
ldst_dn("st8",         "strb  Wd, [Xn, x27]")
ldst_dn("st16",        "strh  Wd, [Xn, x27]")
ldst_dn("st_i32",      "str   Wd, [Xn, x27]")
ldst_dn("st_i64",      "str   Xd, [Xn, x27]")

# QEMU LD/ST are handled in our C runtime rather than with simple gadgets,
# as they're nontrivial.

# Trivial arithmetic.
math_dnm("add" , "add" )
math_dnm("sub" , "sub" )
math_dnm("mul" , "mul" )
math_dnm("div" , "sdiv")
math_dnm("divu", "udiv")

# Division remainder
with_dnm("rem_i32",  "sdiv w27, Wn, Wm", "msub Wd, w27, Wm, Wn")
with_dnm("rem_i64",  "sdiv x27, Xn, Xm", "msub Xd, x27, Xm, Xn")
with_dnm("remu_i32", "udiv w27, Wn, Wm", "msub Wd, w27, Wm, Wn")
with_dnm("remu_i64", "udiv x27, Xn, Xm", "msub Xd, x27, Xm, Xn")

# Trivial logical.
math_dn( "not",  "mvn")
math_dn( "neg",  "neg")
math_dnm("and",  "and")
math_dnm("andc", "bic")
math_dnm("or",   "orr")
math_dnm("orc",  "orn")
math_dnm("xor",  "eor")
math_dnm("eqv",  "eon")
math_dnm("shl",  "lsl")
math_dnm("shr",  "lsr")
math_dnm("sar",  "asr")

# AArch64 lacks a Rotate Left; so we instead rotate right by a negative.
# TODO: validate this?
#math_dnm("rotr", "ror")
#with_dnm("rotl_i32", "neg w27, Wm", "ror Wd, Wn, w27")
#with_dnm("rotl_i64", "neg x27, Xm", "ror Xd, Xn, x27")

# Numeric extension.
math_dn("ext8s",      "sxtb")
with_dn("ext8u",      "and Xd, Xn, #0xff")
math_dn("ext16s",     "sxth")
with_dn("ext16u",     "and Wd, Wn, #0xffff")
with_dn("ext32s_i64", "sxtw Xd, Wn")
with_dn("ext32u_i64", "and Xd, Xn, #0xffffffff")

# Byte swapping.
with_dn("bswap16",    "rev w27, Wn", "lsr Wd, w27, #16")
with_dn("bswap32",    "rev Wd, Wn")
with_dn("bswap64",    "rev Xd, Xn")

# Memory barriers.
simple("mb_all", "dmb ish")
simple("mb_st",  "dmb ishst")
simple("mb_ld",  "dmb ishld")

# Thunks for QEMU_LD.
ld_thunk("qemu_ld_ub",   "_helper_ret_ldub_mmu")
ld_thunk("qemu_ld_sb",   "_helper_ret_ldub_mmu_signed")
ld_thunk("qemu_ld_leuw", "_helper_le_lduw_mmu")
ld_thunk("qemu_ld_lesw", "_helper_le_lduw_mmu_signed")
ld_thunk("qemu_ld_leul", "_helper_le_ldul_mmu")
ld_thunk("qemu_ld_lesl", "_helper_le_ldul_mmu_signed")
ld_thunk("qemu_ld_leq",  "_helper_le_ldq_mmu")
ld_thunk("qemu_ld_beuw", "_helper_be_lduw_mmu")
ld_thunk("qemu_ld_besw", "_helper_be_lduw_mmu_signed")
ld_thunk("qemu_ld_beul", "_helper_be_ldul_mmu")
ld_thunk("qemu_ld_besl", "_helper_be_ldul_mmu_signed")
ld_thunk("qemu_ld_beq",  "_helper_be_ldq_mmu")

# Thunks for QEMU_ST.
st_thunk("qemu_st_ub",   "_helper_ret_stb_mmu")
st_thunk("qemu_st_leuw", "_helper_le_stw_mmu")
st_thunk("qemu_st_leul", "_helper_le_stl_mmu")
st_thunk("qemu_st_leq",  "_helper_le_stq_mmu")
st_thunk("qemu_st_beuw", "_helper_be_stw_mmu")
st_thunk("qemu_st_beul", "_helper_be_stl_mmu")
st_thunk("qemu_st_beq",  "_helper_be_stq_mmu")

# Statistics.
print(f"\nGenerated {gadgets} gadgets with {instructions} instructions ({instructions * 4} B).\n", file=sys.stderr)
