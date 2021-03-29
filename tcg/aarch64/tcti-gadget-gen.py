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
ARCH_CONDITION_CODES = ["eq", "ne", "lt", "ge", "le", "gt", "lo", "pl", "ls", "hi"]

# Statistics.
gadgets      = 0
instructions = 0

def simple(name, *lines):
    """ Generates a simple gadget that needs no per-register specialization. """

    global gadgets, instructions

    gadgets += 1

    # Create our C/ASM framing.
    print(f"__attribute__((naked)) static void gadget_{name}(void)")
    print("{")

    # Add the core gadget
    print("\tasm(")
    for line in lines + EPILOGUE:
        print(f"\t\t\"{line} \\n\"")
        instructions += 1
    print("\t);")

    # End our framing.
    print("}\n")


def with_register_substitutions(name, substitutions, lines):
    """ Generates a collection of gadgtes with register substitutions. """

    def substitutions_for_letter(letter, number, line):
        """ Helper that transforms Wd => w1, implementing gadget substitutions. """
        line = line.replace(f"X{letter}", f"x{number}")
        line = line.replace(f"W{letter}", f"w{number}")
        return line
        
    # Generate a list of register-combinations we'll support.
    parameters   = [TCG_REGISTER_NUMBERS] * len(substitutions)
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
        permutation_id = "_r".join(str(number) for number in permutation)
        simple(f"{name}_r{permutation_id}", *new_lines)


def with_dnm(name, *lines):
    """ Generates a collection of gadgets with substitutions for Xd, Xn, and Xm, and equivalents. """
    with_register_substitutions(name, ("d", "n", "m"), lines)

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
                print(f"gadget_{name}_r{d}_r{n}_r{m}", end=", ")

            print("},")
        print("\t},")
    print("};")


def with_pair(name, substitutions, lines):
    """ Generates a collection of gadgets with two subtstitutions."""
    with_register_substitutions(name, substitutions, lines)

    # Print out an array that contains all of our gadgets, for lookup.
    print(f"void* gadget_{name}[{TCG_REGISTER_COUNT}][{TCG_REGISTER_COUNT}] = ", end="")
    print("{")

    # N array
    for a in TCG_REGISTER_NUMBERS:
        print("\t\t{", end="")

        # M array
        for b in TCG_REGISTER_NUMBERS:
            print(f"gadget_{name}_r{a}_r{b}", end=", ")

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
    with_pair(name, ('n', 'm',), lines)


def with_dn(name, *lines):
    """ Generates a collection of gadgets with substitutions for Xd, and Xn, and equivalents. """
    with_pair(name, ('d', 'n',), lines)


def immediate32_dn(name, *lines):
    """ Generates a collection of gadgets with substitutions for Xd, and Xn, and equivalents. 
    
    This variant automatically loads a 32b immediate into x27.
    """
    with_dn(name, "ldrsw x27, [x28], #4", *lines)


def with_single(name, substitution, lines):
    """ Generates a collection of gadgets with two subtstitutions."""
    with_register_substitutions(name, (substitution,), lines)

    # Print out an array that contains all of our gadgets, for lookup.
    print(f"void* gadget_{name}[{TCG_REGISTER_COUNT}] = ", end="")
    print("{")

    for n in TCG_REGISTER_NUMBERS:
        print(f"gadget_{name}_r{n}", end=", ")

    print("};")


def with_d(name, *lines):
    """ Generates a collection of gadgets with substitutions for Xd. """
    with_single(name, 'd', lines)


#
# Gadget definitions.
#


print("/* Automatically generated by tcti-gadget-gen.py. Do not edit. */\n")

# Call a C language helper function by address.
simple("call",
    # Get our C runtime function's location as a pointer-sized immediate...
    "ldr x27, [x28], #8",
    # ... and call it using AArch64 calling conventions.
    "bl x27"
)

# Branch to a given immediate address.
simple("br",
    # Use our immediate argument as our new bytecode-pointer location.
    # We assume our TCG generator always issues 
    "ldr x27, [x28], #8",
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

    for name in (f'brcond_i32_{condition}', f'brcond_i64_{condition}'):

        # Branches iff a given comparison is true.
        with_nm(name,
            # Perform our comparison and conditional branch.
            "subs Wzr, Wn, Wm",
            f"b{condition} 1f",

            "0:", # not taken
                # Consume the branch target, without using it.
                "add x28, x28, #8",

                # Perform our end-of-instruction epilogue.
                *EPILOGUE,

            "1:" # taken
                # Update our bytecode pointer to take the label.
                "ldr x28, [x28]"
        )


# MOV variants.
with_dn("mov_i32",     "mov Wd, Wn")
with_dn("mov_i64",     "mov Xd, Xn")
with_d("tci_movi_i32", "ldr w27, [x28], #4", "mov Wd, w27")
with_d("tci_movi_i64", "ldr x27, [x28], #8", "mov Xd, x27")

# LOAD variants.
immediate32_dn("ld8u",      "ldrb  Wd, [Xn, x27]")
immediate32_dn("ld8s",      "ldrsb Wd, [Xn, x27]")
immediate32_dn("ld16u",     "ldrh  Wd, [Xn, x27]")
immediate32_dn("ld16s",     "ldrsh Wd, [Xn, x27]")
immediate32_dn("ld32u",     "ldr   Wd, [Xn, x27]")
immediate32_dn("ld32s_i64", "ldrsw Xd, [Xn, x27]")
immediate32_dn("ld_i64",    "ldr   Xd, [Xn, x27]")

# STORE variants.
immediate32_dn("st8",         "strb  Wd, [Xn, x27]")
immediate32_dn("st16",        "strh  Wd, [Xn, x27]")
immediate32_dn("st_i32",      "str   Wd, [Xn, x27]")
immediate32_dn("st_i64",      "str   Xd, [Xn, x27]")

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
math_dnm("or",   "orr")
math_dnm("xor",  "eor")
math_dnm("shl",  "lsl")
math_dnm("shr",  "lsr")
math_dnm("sar",  "asr")
math_dnm("rotr", "ror")
# Note: we use the same gadget for ROTL and ROTR; but with IR backend changing the constant.

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

# Not currently implementing DEPOSIT.

# Statistics.
print(f"\nGenerated {gadgets} gadgets with {instructions} instructions ({instructions * 4} B).\n", file=sys.stderr)
