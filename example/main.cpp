// Verifying an authentication tag, and clearing the key afterwards.
//
//   make demo
#include "ctsafe/ctsafe.hpp"

#include <array>
#include <cstdio>
#include <cstring>

namespace {

struct session {
    std::array<std::uint8_t, 32> key;
    std::array<std::uint8_t, 16> tag;
};

bool accept(const session& s, const std::array<std::uint8_t, 16>& presented) {
    // Not memcmp: it returns on the first differing byte, and the time it takes
    // tells an attacker how many bytes they guessed right.
    return ctsafe::equals(s.tag.data(), presented.data(), s.tag.size());
}

}  // namespace

int main() {
    session s{};
    s.key.fill(0x5A);
    s.tag.fill(0xA5);

    auto correct = s.tag;
    auto wrong_at_the_end = s.tag;
    wrong_at_the_end[15] ^= 0x01;
    auto wrong_at_the_start = s.tag;
    wrong_at_the_start[0] ^= 0x01;

    std::printf("correct tag            accepted=%d\n", accept(s, correct));
    std::printf("wrong in the last byte accepted=%d\n", accept(s, wrong_at_the_end));
    std::printf("wrong in the first     accepted=%d\n", accept(s, wrong_at_the_start));
    std::printf("  (all three read all 16 bytes; memcmp would not)\n\n");

    std::printf("key before erase       zero=%d\n", ctsafe::is_zero(s.key.data(), s.key.size()));
    ctsafe::erase_object(s);
    std::printf("key after erase        zero=%d\n", ctsafe::is_zero(s.key.data(), s.key.size()));
    std::printf("  (built at -O2, where a plain memset would be free to vanish)\n");
    return 0;
}
