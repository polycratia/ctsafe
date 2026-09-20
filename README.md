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
one. The test suite runs at `-O2` as well as under the sanitizers, because an
erasure that only survives at `-O0` is precisely the bug.

**The guard erases once, on the way out of the scope it was declared in.**
`secret_span` holds a pointer and a length, not the buffer, and the erase
belongs to exactly one span: moving it hands the duty over and leaves the source
empty, so nothing is cleared twice and nothing is left behind. `erase_now()`
clears early; `release()` hands the duty back to the caller.

On Windows the header includes `<windows.h>` to reach `SecureZeroMemory`; define
`CTSAFE_NO_WINDOWS_H` to keep it out of the translation unit and take the
fallback instead.

## What it does not guarantee, stated plainly

**It is not proof of constant time.** A unit test cannot demonstrate that; only
reading the generated instructions can, and even then the CPU has the last word
— caches, branch prediction and speculative execution are outside a portable
header's reach. What this gives you is source that does not *ask* the compiler
to leak, and a barrier that stops the two specific optimisations that break
these routines.

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
| Implemented | byte masks (`eq`, `select`, `mask_from_bool`), branch-free `select` and `copy_if` over buffers, constant-time `equals` over spans or a pointer and a length, `is_zero`, non-removable `erase` and `erase_object` over the platform's own secure-zero routine, a `secret_span` guard that erases on scope exit and refuses comparison and streaming |
| Not yet | constant-time integer comparison and conditional swap for bignum code, an owning buffer that allocates and erases |

## Development

```bash
make test        # sanitizers, -O0
make optimized   # the same suite at -O2, where a naive erase would vanish
make demo
```

## License

MIT

Maintained by [polycratia](https://polycratia.com).
