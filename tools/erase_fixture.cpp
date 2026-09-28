// The fixtures the disassembly check reads.
//
// Three functions that differ only in how they clear a buffer nothing reads
// afterwards, which is the exact shape the optimizer is allowed to delete. The
// filler byte differs per function so that identical-code folding cannot merge
// them into one symbol once the naive clear has been deleted, and the call in
// the middle keeps the buffer live up to the clear: the object is compiled with
// -c and never linked, so ctsafe_fixture_use is declared and never defined.
//
//   sh tools/erase_disasm.sh
#include "ctsafe/ctsafe.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace {
constexpr std::size_t key_bytes = 64;
}  // namespace

extern "C" void ctsafe_fixture_use(const void* data, std::size_t length);

// The floor: everything the other two do, minus the clear.
extern "C" void ctsafe_fixture_baseline(std::uint8_t seed) {
    std::uint8_t key[key_bytes];
    std::memset(key, seed ^ 0x11, sizeof key);
    ctsafe_fixture_use(key, sizeof key);
}

extern "C" void ctsafe_fixture_ctsafe(std::uint8_t seed) {
    std::uint8_t key[key_bytes];
    std::memset(key, seed ^ 0x22, sizeof key);
    ctsafe_fixture_use(key, sizeof key);
    ctsafe::erase(key, sizeof key);
}

// CWE-14 itself, written on purpose: the control the check has to catch being
// deleted, because a check that cannot notice a missing store has not noticed a
// surviving one either.
extern "C" void ctsafe_fixture_naive(std::uint8_t seed) {
    std::uint8_t key[key_bytes];
    std::memset(key, seed ^ 0x33, sizeof key);
    ctsafe_fixture_use(key, sizeof key);
    std::memset(key, 0, sizeof key);
}
