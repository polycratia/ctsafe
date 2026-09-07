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
  (built at -O2, where a plain memset would be free to vanish)
```

## Use

```cpp
#include "ctsafe/ctsafe.hpp"

// Spans: both lengths travel with the data, so the size is never retyped.
if (ctsafe::equals(expected_tag, presented_tag)) { /* accept */ }

// Or a pointer and a length, when that is what the caller has.
if (ctsafe::equals(mac, expected, 16)) { /* accept */ }

ctsafe::erase_object(session);   // size taken from the type, not retyped
```

Header-only, C++17, no allocation, no exceptions.

## What it actually guarantees

**The comparison reads every byte before deciding anything.** No branch depends
on the contents, and the accumulated difference passes through a compiler
barrier so the loop cannot be short-circuited.

**The erasure is emitted.** Stores go through a `volatile` pointer, and a
barrier afterwards stops the whole loop being treated as dead code. The test
suite runs at `-O2` as well as under the sanitizers, because an erasure that
only survives at `-O0` is precisely the bug.

## What it does not guarantee, stated plainly

**It is not proof of constant time.** A unit test cannot demonstrate that; only
reading the generated instructions can, and even then the CPU has the last word
— caches, branch prediction and speculative execution are outside a portable
header's reach. What this gives you is source that does not *ask* the compiler
to leak, and a barrier that stops the two specific optimisations that break
these routines.

**The length is not secret.** The span overload accepts anything with `data()`
and `size()` — `std::array`, `std::vector`, `std::string`, a C array,
`std::span` on C++20 — and answers `false` on a size mismatch before a byte is
read. Buffers of different lengths are a structural error, not a guess to
protect, and reading the shorter one past its end would be worse than the leak
being avoided.

**Without inline assembly the barrier weakens.** On compilers other than GCC and
Clang the `asm` block is unavailable and only the `volatile` stores remain. That
fallback is deliberate and marked in the source rather than silently pretended
away.

## Status

Small on purpose, and unlikely to grow much.

| | |
|---|---|
| Implemented | byte masks (`eq`, `select`), constant-time `equals` over spans or a pointer and a length, `is_zero`, non-removable `erase` and `erase_object` |
| Not yet | constant-time integer comparison and conditional swap for bignum code, a `secure_buffer` type that erases in its destructor |

## Development

```bash
make test        # sanitizers, -O0
make optimized   # the same suite at -O2, where a naive erase would vanish
make demo
```

## License

MIT

Maintained by [polycratia](https://polycratia.com).
