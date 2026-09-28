#!/bin/sh
# Read the instructions the compiler emitted for ctsafe::erase.
#
# A unit test can only see the zeroes, and a compiler is free to produce them
# for the test that reads them back while deleting the same store in a function
# where nothing does. So this checks the code rather than the bytes: the three
# fixtures in tools/erase_fixture.cpp are compiled at each optimisation level
# and their instructions counted.
#
#   baseline   no clear at all             the floor
#   ctsafe     ctsafe::erase               has to sit above the floor
#   naive      memset, the bug on purpose  has to fall to the floor at -O2
#
# The control is why the other two rows are worth reading. A run where the naive
# clear also survived has not shown that ctsafe::erase survived anything; it has
# shown that this build deletes nothing, and it says so instead of passing.
#
#   sh tools/erase_disasm.sh
#   OPT_LEVELS="-O0 -O1 -O2 -O3 -Os" sh tools/erase_disasm.sh

set -eu

CXX=${CXX:-c++}
CXXFLAGS=${CXXFLAGS:--std=c++17 -Wall -Wextra -Werror -Iinclude}
OPT_LEVELS=${OPT_LEVELS:--O0 -O2 -O3}
BUILD=${BUILD:-build}
FIXTURE=${FIXTURE:-tools/erase_fixture.cpp}

OBJDUMP=${OBJDUMP:-}
if [ -z "$OBJDUMP" ]; then
    for candidate in objdump gobjdump llvm-objdump; do
        if command -v "$candidate" >/dev/null 2>&1; then
            OBJDUMP=$candidate
            break
        fi
    done
fi
if [ -z "$OBJDUMP" ]; then
    echo "ctsafe erase disassembly: no objdump found, so this check did not run"
    echo "install binutils or llvm, or point OBJDUMP at a disassembler, and run it again"
    exit 0
fi

# Instructions inside one symbol. Padding is not work, so nops are dropped, and
# relocation lines carry an offset of their own and would otherwise be counted
# as instructions. Consecutive headers are one block: a folded function is an
# alias, and both names name the same code.
instructions() {
    "$OBJDUMP" -dr --no-show-raw-insn "$1" | awk -v want="$2" '
        /^[[:space:]]*$/ { run = 0; next }
        /^[0-9a-fA-F]+[[:space:]]+</ {
            name = $0
            sub(/^[0-9a-fA-F]+[[:space:]]+</, "", name)
            sub(/>:.*$/, "", name)
            if (run == 0) { inside = 0; run = 1 }
            if (name == want || name == "_" want) inside = 1
            next
        }
        /R_[A-Z0-9_]+/ { next }
        inside && /^[[:space:]]*[0-9a-fA-F]+:/ && !/nop/ && !/data16/ { count++ }
        END { print count + 0 }
    '
}

# Which routine the erase reached, taken from the relocations rather than
# guessed, so the report names the row of the table this build took.
call_targets() {
    "$OBJDUMP" -dr --no-show-raw-insn "$1" | awk -v want="$2" '
        /^[[:space:]]*$/ { run = 0; next }
        /^[0-9a-fA-F]+[[:space:]]+</ {
            name = $0
            sub(/^[0-9a-fA-F]+[[:space:]]+</, "", name)
            sub(/>:.*$/, "", name)
            if (run == 0) { inside = 0; run = 1 }
            if (name == want || name == "_" want) inside = 1
            next
        }
        inside && /R_[A-Z0-9_]+/ {
            target = $NF
            sub(/[-+]0x[0-9a-fA-F]+$/, "", target)
            sub(/^_/, "", target)
            if (target == "ctsafe_fixture_use" || target in seen) next
            seen[target] = 1
            out = (out == "" ? target : out ", " target)
        }
        END { print out }
    '
}

demangle() {
    if command -v c++filt >/dev/null 2>&1; then
        c++filt
    else
        cat
    fi
}

mkdir -p "$BUILD"
printf 'ctsafe erase disassembly: %s at %s, read with %s\n\n' "$CXX" "$OPT_LEVELS" "$OBJDUMP"

levels=0
unexpected=0
for level in $OPT_LEVELS; do
    levels=$((levels + 1))
    object="$BUILD/erase_fixture$level.o"
    $CXX $CXXFLAGS "$level" -c "$FIXTURE" -o "$object"

    floor=$(instructions "$object" ctsafe_fixture_baseline)
    kept=$(instructions "$object" ctsafe_fixture_ctsafe)
    control=$(instructions "$object" ctsafe_fixture_naive)
    targets=$(call_targets "$object" ctsafe_fixture_ctsafe | demangle)

    printf '%s\n' "$level"
    if [ "$floor" -eq 0 ] || [ "$kept" -eq 0 ]; then
        printf '  the fixtures are not in the disassembly, so nothing here was read\n\n'
        unexpected=$((unexpected + 1))
        continue
    fi

    printf '  no erase, the floor   %4d instructions\n' "$floor"
    if [ -n "$targets" ]; then
        printf '  ctsafe::erase         %4d instructions  calls %s\n' "$kept" "$targets"
    else
        printf '  ctsafe::erase         %4d instructions\n' "$kept"
    fi
    printf '  memset, the control   %4d instructions\n' "$control"

    if [ "$kept" -le "$floor" ]; then
        printf '  NOTHING SURVIVED - the erase left no instructions behind\n\n'
        unexpected=$((unexpected + 1))
        continue
    fi

    if [ "$control" -le "$floor" ]; then
        printf '  emitted, and the control was deleted: the check can tell the two apart\n\n'
    elif [ "$level" = "-O0" ]; then
        printf '  emitted; at -O0 nothing is deleted, so this level decides nothing\n\n'
    else
        printf '  emitted, but the control survived too, so this level is blind\n\n'
        unexpected=$((unexpected + 1))
    fi
done

printf 'ctsafe erase disassembly: %d levels, %d unexpected\n' "$levels" "$unexpected"
[ "$unexpected" -eq 0 ] || exit 1
