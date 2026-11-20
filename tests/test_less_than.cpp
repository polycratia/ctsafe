// The comparisons that answer with a mask: equals_mask, and less_than over
// equal-width big-endian magnitudes.
//
// Its own translation unit because what has to be covered here is arithmetic
// over borrow chains rather than the behaviour of a buffer, and the interesting
// cases are exhaustive loops that would drown the rest of the suite.
//
//   make test
#include "ctsafe/ctsafe.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

#include "harness.hpp"

namespace {

// Reproducible, so a failure names the same values on the next run.
class lcg {
public:
    explicit lcg(std::uint64_t seed) noexcept : state_(seed) {}

    std::uint8_t byte() noexcept {
        state_ = state_ * 6364136223846793005ULL + 1442695040888963407ULL;
        return static_cast<std::uint8_t>(state_ >> 56);
    }

    void fill(std::uint8_t* out, std::size_t length) noexcept {
        for (std::size_t i = 0; i < length; ++i) out[i] = byte();
    }

private:
    std::uint64_t state_;
};

// The order less_than has to agree with, written the way a test is allowed to
// write it: returning on the first differing byte, which is exactly what the
// routine under test may not do.
[[nodiscard]] bool reference_below(const std::uint8_t* a, const std::uint8_t* b,
                                  std::size_t length) {
    for (std::size_t i = 0; i < length; ++i) {
        if (a[i] != b[i]) return a[i] < b[i];
    }
    return false;
}

void equals_mask_answers_with_a_mask() {
    const std::array<std::uint8_t, 4> tag{0x01, 0x02, 0x03, 0x04};
    auto same = tag;
    auto last_byte_differs = tag;
    last_byte_differs[3] ^= 0x01;
    auto first_byte_differs = tag;
    first_byte_differs[0] ^= 0x80;

    CHECK(ctsafe::equals_mask(tag.data(), same.data(), tag.size()) == 0xFF);
    CHECK(ctsafe::equals_mask(tag.data(), last_byte_differs.data(), tag.size()) == 0x00);
    CHECK(ctsafe::equals_mask(tag.data(), first_byte_differs.data(), tag.size()) == 0x00);
    CHECK(ctsafe::equals_mask(nullptr, nullptr, 0) == 0xFF);
}

// The answer is one of two values and never a third, at every position and for
// a difference in any bit: the accumulator is folded into a byte before the
// arithmetic, so a difference that only touched the top bit is the one a lost
// sign would hide.
void equals_mask_answers_only_in_masks() {
    std::array<std::uint8_t, 64> left{};
    lcg rng(0x6D61736B01ULL);
    rng.fill(left.data(), left.size());

    int wrong = 0;
    for (std::size_t i = 0; i < left.size(); ++i) {
        for (int difference : {0x01, 0x80, 0xFF}) {
            auto right = left;
            right[i] = static_cast<std::uint8_t>(right[i] ^ difference);
            if (ctsafe::equals_mask(left.data(), right.data(), left.size()) != 0x00) ++wrong;
        }
    }
    CHECK(wrong == 0);
    CHECK(ctsafe::equals_mask(left.data(), left.data(), left.size()) == 0xFF);
}

void equals_mask_over_spans_takes_the_length_from_the_buffer() {
    const std::array<std::uint8_t, 4> tag{0x01, 0x02, 0x03, 0x04};
    const std::vector<unsigned char> from_a_vector{0x01, 0x02, 0x03, 0x04};
    const std::array<std::uint8_t, 5> longer{0x01, 0x02, 0x03, 0x04, 0x00};

    CHECK(ctsafe::equals_mask(tag, from_a_vector) == 0xFF);
    CHECK(ctsafe::equals_mask(tag, longer) == 0x00);
    CHECK(ctsafe::equals_mask(longer, tag) == 0x00);
}

// A mismatch is answered before a byte is read, and an empty side is the case
// where a routine that answered by reading the other buffer would read all of
// it. The bool and the mask have to agree about that too.
void equals_mask_over_spans_rejects_a_length_mismatch() {
    const std::array<std::uint8_t, 4> tag{0x01, 0x02, 0x03, 0x04};
    const std::vector<unsigned char> nothing;

    CHECK(ctsafe::equals_mask(tag, nothing) == 0x00);
    CHECK(ctsafe::equals_mask(nothing, tag) == 0x00);
    CHECK(ctsafe::equals_mask(nothing, nothing) == 0xFF);
    CHECK(ctsafe::equals_mask(ctsafe::byte_view(), ctsafe::byte_view()) == 0xFF);
    CHECK(ctsafe::equals(tag, nothing) == (ctsafe::equals_mask(tag, nothing) == 0xFF));
}

// equals is the mask with the test moved to the one place a bool is wanted, so
// the two can never disagree about an answer.
void equals_is_its_own_mask_with_the_test_at_the_end() {
    std::array<std::uint8_t, 8> left{};
    left.fill(0x5A);

    int disagreed = 0;
    for (std::size_t i = 0; i < left.size(); ++i) {
        auto right = left;
        right[i] ^= 0x80;
        const bool same = ctsafe::equals(left.data(), right.data(), left.size());
        if (same != (ctsafe::equals_mask(left.data(), right.data(), left.size()) == 0xFF)) {
            ++disagreed;
        }
        CHECK(!same);
    }
    CHECK(disagreed == 0);
    CHECK(ctsafe::equals(left, left) == (ctsafe::equals_mask(left, left) == 0xFF));
}

// The shape the mask exists for: a decision taken on a secret comparison with
// no bool in between for the compiler to branch on.
void equals_mask_drives_a_masked_copy_without_a_bool() {
    std::array<std::uint8_t, 16> expected{};
    expected.fill(0xA5);
    auto presented = expected;

    std::array<std::uint8_t, 32> session{};
    std::array<std::uint8_t, 32> derived{};
    derived.fill(0x27);

    ctsafe::copy_if(ctsafe::equals_mask(expected, presented), session.data(), derived.data(),
                    session.size());
    CHECK(ctsafe::equals(session, derived));

    presented[15] ^= 0x01;
    std::array<std::uint8_t, 32> rejected{};
    rejected.fill(0x99);
    ctsafe::copy_if(ctsafe::equals_mask(expected, presented), session.data(), rejected.data(),
                    session.size());
    CHECK(ctsafe::equals(session, derived));
}

// The borrow has to cross bytes: the bottom byte decides only when every byte
// above it is equal, and a difference up top outranks any number of borrows
// below it.
void less_than_carries_the_borrow_across_bytes() {
    const std::uint8_t zero[3] = {0x00, 0x00, 0x00};
    const std::uint8_t one[3] = {0x00, 0x00, 0x01};
    const std::uint8_t high[3] = {0x01, 0x00, 0x00};
    const std::uint8_t just_below[3] = {0x00, 0xFF, 0xFF};
    const std::uint8_t top[3] = {0xFF, 0xFF, 0xFF};

    CHECK(ctsafe::less_than(zero, one, 3) == 0xFF);
    CHECK(ctsafe::less_than(one, zero, 3) == 0x00);

    // 0x00FFFF < 0x010000: the borrow runs through two whole bytes before the
    // top one answers.
    CHECK(ctsafe::less_than(just_below, high, 3) == 0xFF);
    CHECK(ctsafe::less_than(high, just_below, 3) == 0x00);

    // The same answer with no borrow in the middle byte at all.
    CHECK(ctsafe::less_than(one, high, 3) == 0xFF);
    CHECK(ctsafe::less_than(high, one, 3) == 0x00);

    CHECK(ctsafe::less_than(high, top, 3) == 0xFF);
    CHECK(ctsafe::less_than(top, high, 3) == 0x00);
    CHECK(ctsafe::less_than(zero, top, 3) == 0xFF);
}

// The longest chain the routine can be given here: one magnitude is a single
// set bit in the top byte, the other is every bit below it, so the borrow is
// owed by all thirty-one bytes before the answer exists.
void less_than_carries_a_borrow_the_whole_width() {
    std::array<std::uint8_t, 32> high{};
    std::array<std::uint8_t, 32> just_below{};
    high[0] = 0x01;
    for (std::size_t i = 1; i < just_below.size(); ++i) just_below[i] = 0xFF;

    CHECK(ctsafe::less_than(just_below.data(), high.data(), high.size()) == 0xFF);
    CHECK(ctsafe::less_than(high.data(), just_below.data(), high.size()) == 0x00);

    // And the shortest: a difference in the least significant byte of a wide
    // magnitude, which decides only because nothing above it did.
    std::array<std::uint8_t, 32> a{};
    a.fill(0x55);
    auto b = a;
    b[31] = 0x56;
    CHECK(ctsafe::less_than(a.data(), b.data(), a.size()) == 0xFF);
    CHECK(ctsafe::less_than(b.data(), a.data(), a.size()) == 0x00);

    b = a;
    b[0] = 0x56;
    CHECK(ctsafe::less_than(a.data(), b.data(), a.size()) == 0xFF);
    CHECK(ctsafe::less_than(b.data(), a.data(), a.size()) == 0x00);
}

void less_than_is_clear_for_equal_magnitudes() {
    const std::uint8_t a[4] = {0x12, 0x34, 0x56, 0x78};
    const std::uint8_t b[4] = {0x12, 0x34, 0x56, 0x78};

    CHECK(ctsafe::less_than(a, b, 4) == 0x00);
    CHECK(ctsafe::less_than(b, a, 4) == 0x00);
    CHECK(ctsafe::less_than(a, a, 4) == 0x00);
    CHECK(ctsafe::less_than(nullptr, nullptr, 0) == 0x00);  // nothing is below nothing
}

// Big-endian means the leading bytes are the most significant ones, so leading
// zeroes are padding rather than value.
void leading_zeroes_do_not_change_the_order() {
    const std::uint8_t small[4] = {0x00, 0x00, 0x00, 0x05};
    const std::uint8_t large[4] = {0x00, 0x00, 0x01, 0x00};

    CHECK(ctsafe::less_than(small, large, 4) == 0xFF);
    CHECK(ctsafe::less_than(large, small, 4) == 0x00);
}

// Every pair of single bytes against the order the language already defines.
// Counted into one check rather than 65536 of them, so the report stays
// readable and a failure still names the routine.
void less_than_agrees_with_integer_order_over_every_byte_pair() {
    int wrong = 0;
    for (unsigned a = 0; a < 256; ++a) {
        for (unsigned b = 0; b < 256; ++b) {
            const std::uint8_t left = static_cast<std::uint8_t>(a);
            const std::uint8_t right = static_cast<std::uint8_t>(b);
            if (ctsafe::less_than(&left, &right, 1) != ctsafe::mask_from_bool(a < b)) ++wrong;
        }
    }
    CHECK(wrong == 0);
}

// Four bytes against the same order, over neighbours and steps of exactly one
// byte boundary — the values where a borrow that stops early is still right
// about everything else.
void less_than_agrees_with_integer_order_over_four_bytes() {
    auto encode = [](std::uint32_t value, std::uint8_t* out) {
        out[0] = static_cast<std::uint8_t>(value >> 24);
        out[1] = static_cast<std::uint8_t>(value >> 16);
        out[2] = static_cast<std::uint8_t>(value >> 8);
        out[3] = static_cast<std::uint8_t>(value);
    };

    std::uint64_t state = 0x63747361666531ULL;
    auto next = [&state]() -> std::uint32_t {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        return static_cast<std::uint32_t>(state >> 32);
    };

    const std::uint32_t steps[] = {0u, 1u, 0xFFFFFFFFu, 0x100u, 0xFFFFFF00u, 0x1000000u};

    int wrong = 0;
    for (int trial = 0; trial < 2048; ++trial) {
        const std::uint32_t a = next();
        for (std::uint32_t step : steps) {
            const std::uint32_t b = a + step;
            std::uint8_t left[4];
            std::uint8_t right[4];
            encode(a, left);
            encode(b, right);
            if (ctsafe::less_than(left, right, sizeof left) != ctsafe::mask_from_bool(a < b)) {
                ++wrong;
            }
            if (ctsafe::less_than(right, left, sizeof right) != ctsafe::mask_from_bool(b < a)) {
                ++wrong;
            }
        }
    }
    CHECK(wrong == 0);
}

// Widths that are not a whole number of words, and widths wider than one: a
// loop the compiler unrolls or vectorises gets a head and a tail that the
// round widths above never reach.
void less_than_holds_at_every_width() {
    lcg rng(0x77696474ULL);
    const std::size_t widths[] = {1, 2, 3, 7, 8, 9, 15, 16, 31, 32};

    int wrong = 0;
    for (std::size_t width : widths) {
        std::uint8_t left[32] = {};
        std::uint8_t right[32] = {};
        rng.fill(left, width);

        // A difference in the least significant byte, then in the most
        // significant one, then none at all.
        std::memcpy(right, left, width);
        right[width - 1] = static_cast<std::uint8_t>(left[width - 1] | 0x01);
        left[width - 1] = static_cast<std::uint8_t>(right[width - 1] ^ 0x01);
        if (ctsafe::less_than(left, right, width) != 0xFF) ++wrong;
        if (ctsafe::less_than(right, left, width) != 0x00) ++wrong;

        std::memcpy(right, left, width);
        right[0] = static_cast<std::uint8_t>(left[0] | 0x80);
        left[0] = static_cast<std::uint8_t>(right[0] ^ 0x80);
        if (ctsafe::less_than(left, right, width) != 0xFF) ++wrong;
        if (ctsafe::less_than(right, left, width) != 0x00) ++wrong;

        std::memcpy(right, left, width);
        if (ctsafe::less_than(left, right, width) != 0x00) ++wrong;
        if (ctsafe::equals_mask(left, right, width) != 0xFF) ++wrong;
    }
    CHECK(wrong == 0);
}

// Random magnitudes against a reference that is allowed to return early, with a
// shared prefix on some of them, because a borrow that stops once the answer is
// known is still right about everything except its timing.
void less_than_agrees_with_a_reference_over_random_magnitudes() {
    lcg rng(0x6C7420726566ULL);
    const std::size_t widths[] = {1, 2, 7, 8, 31, 32};

    int wrong = 0;
    for (std::size_t width : widths) {
        for (int trial = 0; trial < 256; ++trial) {
            std::uint8_t a[32] = {};
            std::uint8_t b[32] = {};
            rng.fill(a, width);
            rng.fill(b, width);
            if (trial % 4 == 0) {
                for (std::size_t i = 0; i < width / 2; ++i) b[i] = a[i];
            }
            if (ctsafe::less_than(a, b, width) !=
                ctsafe::mask_from_bool(reference_below(a, b, width))) {
                ++wrong;
            }
            if (ctsafe::less_than(b, a, width) !=
                ctsafe::mask_from_bool(reference_below(b, a, width))) {
                ++wrong;
            }
        }
    }
    CHECK(wrong == 0);
}

// Below, above and equal are the three answers, and exactly one of them holds
// for any pair — the property a caller selecting on two of them relies on, and
// the one a borrow left set at the end of an equal comparison would break.
void exactly_one_of_below_above_and_equal_holds() {
    lcg rng(0x74726963680ULL);
    constexpr std::size_t width = 16;

    int wrong = 0;
    for (int trial = 0; trial < 512; ++trial) {
        std::uint8_t a[width] = {};
        std::uint8_t b[width] = {};
        rng.fill(a, width);
        rng.fill(b, width);
        if (trial % 3 == 0) std::memcpy(b, a, width);

        const ctsafe::mask below = ctsafe::less_than(a, b, width);
        const ctsafe::mask above = ctsafe::less_than(b, a, width);
        const ctsafe::mask same = ctsafe::equals_mask(a, b, width);

        if (below != 0x00 && below != 0xFF) ++wrong;
        if (above != 0x00 && above != 0xFF) ++wrong;
        if (same != 0x00 && same != 0xFF) ++wrong;
        if ((below == 0xFF) + (above == 0xFF) + (same == 0xFF) != 1) ++wrong;
    }
    CHECK(wrong == 0);
}

// Acting on an ordering without branching on it: the smaller of two magnitudes,
// picked by the mask the comparison returned.
void less_than_selects_the_smaller_magnitude() {
    const std::uint8_t a[4] = {0x00, 0x10, 0x00, 0x00};
    const std::uint8_t b[4] = {0x00, 0x0F, 0xFF, 0xFF};
    std::uint8_t smaller[4] = {};

    ctsafe::select(ctsafe::less_than(a, b, 4), smaller, a, b, 4);
    CHECK(ctsafe::equals(smaller, b, 4));

    ctsafe::select(ctsafe::less_than(b, a, 4), smaller, b, a, 4);
    CHECK(ctsafe::equals(smaller, b, 4));
}

// The two routines composed the way a ladder composes them: order a pair in
// place, with the comparison feeding the exchange and no bool anywhere between
// them. Both buffers keep their values whichever way the mask went.
void a_masked_swap_orders_two_magnitudes() {
    lcg rng(0x6C61646465ULL);
    constexpr std::size_t width = 8;

    int wrong = 0;
    for (int trial = 0; trial < 256; ++trial) {
        std::uint8_t a[width] = {};
        std::uint8_t b[width] = {};
        rng.fill(a, width);
        rng.fill(b, width);
        if (trial % 5 == 0) std::memcpy(b, a, width);

        std::uint8_t a_before[width];
        std::uint8_t b_before[width];
        std::memcpy(a_before, a, width);
        std::memcpy(b_before, b, width);

        ctsafe::swap_if(ctsafe::less_than(b, a, width), a, b, width);

        if (ctsafe::less_than(b, a, width) != 0x00) ++wrong;

        const bool kept = ctsafe::equals(a, a_before, width) && ctsafe::equals(b, b_before, width);
        const bool exchanged =
            ctsafe::equals(a, b_before, width) && ctsafe::equals(b, a_before, width);
        if (!kept && !exchanged) ++wrong;
    }
    CHECK(wrong == 0);
}

}  // namespace

int main() {
    equals_mask_answers_with_a_mask();
    equals_mask_answers_only_in_masks();
    equals_mask_over_spans_takes_the_length_from_the_buffer();
    equals_mask_over_spans_rejects_a_length_mismatch();
    equals_is_its_own_mask_with_the_test_at_the_end();
    equals_mask_drives_a_masked_copy_without_a_bool();
    less_than_carries_the_borrow_across_bytes();
    less_than_carries_a_borrow_the_whole_width();
    less_than_is_clear_for_equal_magnitudes();
    leading_zeroes_do_not_change_the_order();
    less_than_agrees_with_integer_order_over_every_byte_pair();
    less_than_agrees_with_integer_order_over_four_bytes();
    less_than_holds_at_every_width();
    less_than_agrees_with_a_reference_over_random_magnitudes();
    exactly_one_of_below_above_and_equal_holds();
    less_than_selects_the_smaller_magnitude();
    a_masked_swap_orders_two_magnitudes();
    return harness::report("ctsafe masks");
}
