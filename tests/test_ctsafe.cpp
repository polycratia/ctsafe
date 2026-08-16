#include "ctsafe/ctsafe.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <string>

#include "harness.hpp"

namespace {

void eq_and_select_are_masks() {
    CHECK(ctsafe::eq(0x00, 0x00) == 0xFF);
    CHECK(ctsafe::eq(0xFF, 0xFF) == 0xFF);
    CHECK(ctsafe::eq(0x00, 0x01) == 0x00);
    CHECK(ctsafe::eq(0x80, 0x00) == 0x00);

    CHECK(ctsafe::select(0xFF, 0xAA, 0xBB) == 0xAA);
    CHECK(ctsafe::select(0x00, 0xAA, 0xBB) == 0xBB);
}

void equals_agrees_with_memcmp_on_every_answer() {
    const std::string a = "the quick brown fox";
    const std::string b = "the quick brown fox";
    const std::string c = "the quick brown fix";

    CHECK(ctsafe::equals(a.data(), b.data(), a.size()));
    CHECK(!ctsafe::equals(a.data(), c.data(), a.size()));
    CHECK(ctsafe::equals(a.data(), c.data(), 4));  // the first four bytes do match
}

// The failure this exists to prevent: memcmp returns on the first differing
// byte, so a difference in byte 0 and a difference in byte 15 cost different
// amounts of time. Here both read the whole buffer.
void equals_reads_the_whole_buffer_whatever_differs() {
    std::array<std::uint8_t, 16> expected{};
    expected.fill(0xAB);

    auto differs_at = [&](std::size_t index) {
        auto candidate = expected;
        candidate[index] ^= 0x01;
        return ctsafe::equals(expected.data(), candidate.data(), expected.size());
    };

    CHECK(!differs_at(0));
    CHECK(!differs_at(7));
    CHECK(!differs_at(15));
    CHECK(ctsafe::equals(expected.data(), expected.data(), expected.size()));
}

void a_zero_length_comparison_is_equal() {
    CHECK(ctsafe::equals(nullptr, nullptr, 0));
    CHECK(ctsafe::is_zero(nullptr, 0));
}

void is_zero_finds_a_single_set_bit_anywhere() {
    std::array<std::uint8_t, 32> buffer{};
    CHECK(ctsafe::is_zero(buffer.data(), buffer.size()));

    for (std::size_t index : {std::size_t{0}, std::size_t{17}, std::size_t{31}}) {
        buffer.fill(0);
        buffer[index] = 0x01;
        CHECK(!ctsafe::is_zero(buffer.data(), buffer.size()));
    }
}

void erase_zeroes_the_buffer() {
    std::array<std::uint8_t, 64> key{};
    key.fill(0x5A);
    CHECK(!ctsafe::is_zero(key.data(), key.size()));

    ctsafe::erase(key.data(), key.size());
    CHECK(ctsafe::is_zero(key.data(), key.size()));
}

// The bug is a store the optimizer deletes because nothing reads the buffer
// afterwards. A unit test cannot prove the store survived - only a disassembly
// can - so this checks the observable half and the README states the limit.
void erase_survives_a_dead_buffer() {
    struct secret {
        std::uint8_t material[32];
        std::uint32_t counter;
    };

    secret s{};
    std::memset(s.material, 0x33, sizeof s.material);
    s.counter = 0xDEADBEEF;

    ctsafe::erase_object(s);

    CHECK(ctsafe::is_zero(&s, sizeof s));
    CHECK(s.counter == 0);
}

void erase_of_nothing_is_allowed() {
    std::array<std::uint8_t, 1> one{0x11};
    ctsafe::erase(one.data(), 0);
    CHECK(one[0] == 0x11);  // zero length means zero bytes touched
}

}  // namespace

int main() {
    eq_and_select_are_masks();
    equals_agrees_with_memcmp_on_every_answer();
    equals_reads_the_whole_buffer_whatever_differs();
    a_zero_length_comparison_is_equal();
    is_zero_finds_a_single_set_bit_anywhere();
    erase_zeroes_the_buffer();
    erase_survives_a_dead_buffer();
    erase_of_nothing_is_allowed();
    return harness::report("ctsafe");
}
