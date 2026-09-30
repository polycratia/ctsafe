# ctsafe

Comparisons that do not leak through timing, and erasure the optimizer is not
allowed to delete.

Two bugs, both older than most of the code that still contains them:

```cpp
if (memcmp(mac, expected, 16) == 0) { ... }   // CWE-208
```

`memcmp` returns as soon as two bytes differ. Someone who can time the call
learns how many leading bytes they guessed correctly, and recovers the tag one
byte at a time.

```cpp
memset(key, 0, sizeof key);   // CWE-14, at the end of a function
```

The compiler can see the buffer is dead afterwards and delete the store
entirely, leaving the key in memory for a core dump or the next allocation to
find.

Neither needs a clever fix. Both need a fix the compiler is not permitted to
undo.

```console
$ make demo
correct tag            accepted=1
wrong in the last byte accepted=0
wrong in the first     accepted=0
  (all three read all 16 bytes; memcmp would not)

key before erase       zero=0
key after erase        zero=1
  (erased with explicit_bzero; at -O2 a plain memset would be free to vanish)
```

## Use

```cpp
#include "ctsafe/ctsafe.hpp"

// Spans: both lengths travel with the data, so the size is never retyped.
if (ctsafe::equals(expected_tag, presented_tag)) { /* accept */ }

// Or a pointer and a length, when that is what the caller has.
if (ctsafe::equals(mac, expected, 16)) { /* accept */ }

// Acting on the answer without branching on it: the mask decides which bytes
// land, and the same stores happen either way.
ctsafe::mask accepted = ctsafe::mask_from_bool(ctsafe::equals(expected_tag, presented_tag));
ctsafe::copy_if(accepted, session_key, derived_key, 32);
ctsafe::select(accepted, out, derived_key, fallback_key, 32);

ctsafe::erase_object(session);     // size taken from the type, not retyped
ctsafe::erase_backend_name();      // which routine that erase actually called
```

Bytes that must not outlive the scope holding them get a guard. It erases on
the way out, and the two spellings that leak a secret by accident do not
compile:

```cpp
{
    ctsafe::secret_span secret(key);      // key is a std::array, vector, or C array

    sign(message, secret.data(), secret.size());
    if (ctsafe::equals(secret, presented)) { /* accept */ }

    // secret == presented;   // deleted: that comparison is memcmp underneath
    // std::cerr << secret;   // deleted: a secret does not go to a log
}   // key is zero here
```

Header-only, C++17, no allocation, no exceptions.

## What it actually guarantees

**The comparison reads every byte before deciding anything.** No branch depends
on the contents, and the accumulated difference passes through a compiler
barrier so the loop cannot be short-circuited.

**The choice does not branch on the mask.** `select` and `copy_if` read both
sides and write every byte of the destination whichever way the mask goes, so a
rejected copy costs the same stores as an accepted one. The mask itself passes
through a value barrier first, so the compiler cannot discover what it holds and
rewrite the loop as a branch around a `memcpy` — which would put back exactly
the leak the mask removed.

**The erasure is emitted.** `erase` calls the routine the platform already
provides for exactly this, and only argues with the optimizer itself when there
is none:

| Platform | `erase` calls |
|---|---|
| Windows | `SecureZeroMemory` |
| glibc >= 2.25, OpenBSD, FreeBSD | `explicit_bzero` |
| Annex K available (`__STDC_LIB_EXT1__`) | `memset_s` |
| anything else | stores through a `volatile` pointer |

Every path ends in a compiler barrier — an empty `asm` block with a memory
clobber on GCC and Clang, `_ReadWriteBarrier()` on MSVC — so the buffer cannot
be treated as dead across the call. Which row a build took is reported by
`ctsafe::erase_backend_name()`, because a guarantee you have to guess at is not
one. The suite runs at `-O0`, `-O2` and `-O3` as well as under the sanitizers,
because an erasure that only survives at `-O0` is precisely the bug.

**The guard erases once, on the way out of the scope it was declared in.**
`secret_span` holds a pointer and a length, not the buffer, and the erase
belongs to exactly one span: moving it hands the duty over and leaves the source
empty, so nothing is cleared twice and nothing is left behind. `erase_now()`
clears early; `release()` hands the duty back to the caller.

On Windows the header includes `<windows.h>` to reach `SecureZeroMemory`; define
`CTSAFE_NO_WINDOWS_H` to keep it out of the translation unit and take the
fallback instead.

## Constant time at the source, and the part the CPU keeps

"Constant time" is not one property. It is a claim that has to survive three
layers, and only the first two are within reach of a portable header.

**The source — decided here, and readable.** No branch and no memory address
depends on a secret value. `equals` accumulates every byte and decides
afterwards; `select` and `copy_if` are arithmetic over both sides; nothing here
indexes a table with a secret, which is the shape that turns a cache into an
oracle. This layer is settled by the code in front of you, and reading it is how
you check it.

**The compiler — held at two named points.** Two rewrites undo the source:
deleting a store to a buffer nothing reads again, and recognising a mask well
enough to replace the arithmetic with a branch around a `memcpy`. Both are
blocked where they would happen — `detail::keep` after an erase or a comparison,
`detail::hide` before a masked loop — and both are checked rather than asserted:
`make disasm` reads the emitted erase, `make timing` puts a clock on the masked
copy. Everything else a compiler may do is still permitted. Vectorising the
loop, unrolling it, spilling the accumulator, reordering the two loads: none of
those makes the work depend on the values, but nothing here verifies that for
your compiler either. The instruction stream is the only authority, and the
check in this repository reads it for `erase` alone.

**The CPU — out of reach, and no version of this header changes that.**

| What the hardware decides | What the source can say about it |
|---|---|
| Cache and TLB residency | The addresses touched are the whole buffer, in order, never an index derived from a secret. Whether those lines were already resident is settled before the call. |
| Branch prediction | There is no secret-dependent branch left to mispredict; the loop's own exit is predicted the same way whichever class the input belonged to. |
| Speculative and transient execution | Spectre-class leaks read past the architectural argument entirely. Mitigation belongs to microcode, the kernel and the build flags, not to a comparison loop. |
| Instruction latency by operand | The routines use xor, and, or, a subtract and a shift by a constant, over bytes — fixed latency on mainstream cores. On a core where they are not, the claim fails and this header cannot tell you so. |
| Frequency scaling (Hertzbleed), SMT neighbours, interrupts | Data-dependent frequency and shared-core contention are timing channels the process can neither observe nor suppress. The harness crops that noise; the code cannot remove it. |
| Power, EM and acoustic channels | Not timing at all, and entirely outside the scope of anything written here. |

So the claim in its honest form: *this source does not ask for a data-dependent
path, and the two compiler rewrites that would create one are blocked and
checked.* Turning that into "this binary runs in constant time on this core"
takes reading the disassembly your compiler produced and knowing the latencies
of the CPU that will run it. Where that is not enough — a cipher core, a
bignum ladder, a target with a published attack — the answer is a verified
implementation for that machine, not a portable header.

## Checking that the store survived

A test can only see the zeroes, and it reads them back — which is exactly the
case the optimizer is not allowed to delete. Nothing in a test says what happens
in the function that clears a buffer and then returns. `make disasm` reads the
instructions instead: three functions that differ only in how they clear a
buffer nothing touches afterwards, compiled at each level and counted.

```console
$ make disasm
ctsafe erase disassembly: c++ at -O0 -O2 -O3, read with objdump

-O0
  no erase, the floor     23 instructions
  ctsafe::erase           27 instructions  calls ctsafe::erase(void*, unsigned long)
  memset, the control     27 instructions
  emitted; at -O0 nothing is deleted, so this level decides nothing

-O2
  no erase, the floor     11 instructions
  ctsafe::erase           14 instructions  calls explicit_bzero
  memset, the control     11 instructions
  emitted, and the control was deleted: the check can tell the two apart

-O3
  no erase, the floor     11 instructions
  ctsafe::erase           14 instructions  calls explicit_bzero
  memset, the control     11 instructions
  emitted, and the control was deleted: the check can tell the two apart

ctsafe erase disassembly: 3 levels, 0 unexpected
```

The control is the reason the other two rows mean anything, the same way the
timing harness measures `memcmp`. A `memset` over a dead buffer is a store that
*should* disappear, so a run where it did not is a run that would have reported
the naive spelling as safe; it says it was blind and exits non-zero rather than
passing. What the check covers is `erase`, on the build in front of you, at the
levels in `OPT_LEVELS` — not the comparison, whose instruction stream still has
to be read by hand.

## Putting the timing claim on a clock

`make timing` runs the routines past a statistical harness in the shape of
dudect (Reparaz, Balasch and Verbauwhede, *dude, is my code constant time?*,
2016). Each case times one operation over two classes of input — equal against
one differing byte, a difference in the first byte against the last, all zero
against a single set bit, a mask set against a mask clear — drawing the class at
random before every measurement so that drift cannot line up with one class. The
slow tail where the scheduler lives is cropped at a hundred percentiles, Welch's
t-test is applied to each crop, and the largest `|t|` decides. Above 10 is a
difference; the process exits non-zero, so an unattended run fails rather than
printing a number nobody reads.

```console
$ make timing
ctsafe timing: 6 rounds x 20000 measurements x 4 executions, 1024-byte buffers

equals: equal vs one differing byte
  max |t| = 1.84 across 101 crops, 120000 measurements, 6 rounds
  no difference at |t| > 10 - consistent with constant time

...

control - memcmp: equal vs a difference in the first byte
  max |t| = 148.02 across 101 crops, 20000 measurements, 1 rounds
  difference found, which is what this case is for

ctsafe timing: 5 cases, 0 unexpected
```

The last case is the reason the others are worth reading. A harness that finds
nothing is either measuring a constant-time routine or measuring nothing at all,
and from outside the two look identical, so the suite also measures `memcmp` —
a leak of known size that has to come out significant. When it does not, the run
says it was blind instead of saying it passed.

The binary is built at `-O2` and without the sanitizers, because both `-O0` and
the instrumentation would time something other than what ships. A case that
lands on the wrong side is measured once more with a different seed, since a
loaded machine produces a large `t` without any help from the code, and only the
repeat counts. A `|t|` between 5 and 10 is reported as worth a longer run:
`make timing ROUNDS=40`.

What a clean run establishes is bounded by the machine that produced it: this
build, this core, this load, this seed. It is evidence that no difference large
enough to find was there to find, not evidence that none exists.

## What it does not guarantee, stated plainly

**It is not proof of constant time.** A unit test cannot demonstrate that, and
neither can a header; the three layers above say which part is held where. The
timing harness tries to *disprove* the claim on the machine in front of you and
reports how hard it tried, which is a different and weaker thing than a proof.
What this gives you is source that does not *ask* the compiler to leak, a
barrier that stops the two specific optimisations that break these routines, and
a clock pointed at the result.

**A mask is 0xFF or 0x00, and nothing else.** `select` and `copy_if` are
arithmetic, not a test: handed 0x01 they mix the two sides bit by bit instead of
rejecting it. Masks come from `eq` or `mask_from_bool`; a value invented
elsewhere is a bug no amount of checking inside the loop could catch without
branching on it.

**The length is not secret.** The span overload accepts anything with `data()`
and `size()` — `std::array`, `std::vector`, `std::string`, a C array,
`std::span` on C++20 — and answers `false` on a size mismatch before a byte is
read. Buffers of different lengths are a structural error, not a guess to
protect, and reading the shorter one past its end would be worse than the leak
being avoided.

**Erasing a buffer does not erase its copies.** No routine in the table above
reaches a register spill, a block that `realloc` moved, or a page the kernel has
already written to swap. Erase clears the bytes you name, at the moment you name
them; keeping the secret from being duplicated in the first place is the
caller's problem.

**`secret_span` narrows the mistake rather than closing it.** Deleting `==` and
`<<` stops the two spellings that actually appear in code; `memcmp(secret.data(),
...)` and `printf("%s", secret.data())` are still there to be written, because a
type that hid its bytes entirely could not be used to sign anything. It is also
a guard, not a container: the buffer belongs to whoever declared it, the erase
happens when the guard dies rather than when the buffer does, and the
constructors are explicit so a buffer passed to a function cannot be wrapped
into a temporary that erases it at the end of the statement.

**The last row of the table is weaker than the others.** With no platform
routine and no barrier — a compiler that is neither GCC, Clang nor MSVC — only
the `volatile` stores remain, and the mask handed to `select` stays transparent
to the optimizer. A conforming implementation must emit the stores, but nothing
else is holding it back. That fallback is deliberate, named by
`erase_backend_name()`, and marked in the source rather than silently pretended
away.

## Status

Small on purpose, and unlikely to grow much.

| | |
|---|---|
| Implemented | byte masks (`eq`, `select`, `mask_from_bool`), branch-free `select` and `copy_if` over buffers, constant-time `equals` over spans or a pointer and a length, `is_zero`, non-removable `erase` and `erase_object` over the platform's own secure-zero routine, a `secret_span` guard that erases on scope exit and refuses comparison and streaming, a dudect-style timing harness with a known-leak control, a disassembly check that the erase is still in the instruction stream at `-O2` and `-O3` |
| Not yet | constant-time integer comparison and conditional swap for bignum code, an owning buffer that allocates and erases |

## Development

```bash
make test        # sanitizers, -O0
make matrix      # the same suite at -O0, -O2 and -O3, where a naive erase vanishes
make disasm      # read the emitted erase and check the store is still there
make timing      # the timing harness, at -O2 and without the sanitizers
make demo
make check       # test, matrix, disasm and timing
```

## License

MIT

Maintained by [polycratia](https://polycratia.com).
