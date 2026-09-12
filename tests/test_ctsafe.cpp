#include "ctsafe/ctsafe.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

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

void equals_over_spans_takes_the_length_from_the_buffer() {
    const std::array<std::uint8_t, 4> tag{0x01, 0x02, 0x03, 0x04};
    const std::array<std::uint8_t, 4> same{0x01, 0x02, 0x03, 0x04};
    const std::array<std::uint8_t, 4> last_byte_differs{0x01, 0x02, 0x03, 0x05};
    const std::array<std::uint8_t, 4> first_byte_differs{0x00, 0x02, 0x03, 0x04};

    CHECK(ctsafe::equals(tag, same));
    CHECK(!ctsafe::equals(tag, last_byte_differs));
    CHECK(!ctsafe::equals(tag, first_byte_differs));

    const std::vector<unsigned char> from_a_vector{0x01, 0x02, 0x03, 0x04};
    CHECK(ctsafe::equals(tag, from_a_vector));

    const std::string text = "tag";
    CHECK(ctsafe::equals(text, std::string("tag")));
    CHECK(!ctsafe::equals(text, std::string("tab")));
}

// A tag of the wrong size is a structural error, not a guess to protect, so the
// answer is false rather than a comparison that reads past the shorter buffer.
void spans_of_different_lengths_are_never_equal() {
    const std::array<std::uint8_t, 4> shorter{0x01, 0x02, 0x03, 0x04};
    const std::array<std::uint8_t, 5> longer{0x01, 0x02, 0x03, 0x04, 0x00};

    CHECK(!ctsafe::equals(shorter, longer));
    CHECK(!ctsafe::equals(longer, shorter));
}

void a_span_can_be_built_from_the_shapes_a_caller_has() {
    const std::uint8_t raw[3] = {0xAA, 0xBB, 0xCC};

    CHECK(ctsafe::equals(raw, ctsafe::byte_view(raw, sizeof raw)));
    CHECK(ctsafe::equals(ctsafe::byte_view(), ctsafe::byte_view(nullptr, 0)));
    CHECK(ctsafe::byte_view(raw).size() == 3);
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

// is_zero() could in principle be folded into the erase by a compiler that can
// see both. Reading the bytes back through a volatile pointer cannot be, so
// this check is answered by memory rather than by constant propagation.
void erase_is_visible_through_a_volatile_read() {
    std::array<std::uint8_t, 32> key{};
    key.fill(0x7E);
    ctsafe::erase(key.data(), key.size());

    const volatile std::uint8_t* view = key.data();
    std::uint8_t any = 0;
    for (std::size_t i = 0; i < key.size(); ++i) any = static_cast<std::uint8_t>(any | view[i]);
    CHECK(any == 0);
}

// Which routine did the erasing differs by platform, and so does how much it
// promises. The suite prints the answer instead of leaving it to be assumed.
void the_erase_backend_names_itself() {
    const char* name = ctsafe::erase_backend_name();
    CHECK(name[0] != '\0');
    CHECK((ctsafe::erase_backend_used() == ctsafe::erase_backend::volatile_stores) ==
          (std::strncmp(name, "volatile", 8) == 0));
    std::printf("erase backend: %s\n", name);
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
    equals_over_spans_takes_the_length_from_the_buffer();
    spans_of_different_lengths_are_never_equal();
    a_span_can_be_built_from_the_shapes_a_caller_has();
    a_zero_length_comparison_is_equal();
    is_zero_finds_a_single_set_bit_anywhere();
    erase_zeroes_the_buffer();
    erase_survives_a_dead_buffer();
    erase_is_visible_through_a_volatile_read();
    the_erase_backend_names_itself();
    erase_of_nothing_is_allowed();
    return harness::report("ctsafe");
}
