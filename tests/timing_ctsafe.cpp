// The timing half of the suite: a dudect-style comparison of the distributions
// for equal and unequal inputs, and a control that has to come out significant
// so that a clean run means the harness was looking at something.
//
//   make timing
#include "ctsafe/ctsafe.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <vector>

#include "timing.hpp"

namespace {

// Every answer the operations produce goes through here. A volatile store the
// compiler has to emit, fed by a volatile load, keeps a comparison nobody reads
// from being deleted and keeps the calls inside the timed loop.
volatile std::uint8_t sink = 0;

constexpr std::size_t buffer_bytes = 1024;

void fill_random(std::mt19937_64& rng, std::vector<std::uint8_t>& buffer) {
    for (std::size_t i = 0; i < buffer.size();) {
        std::uint64_t word = rng();
        for (int byte = 0; byte < 8 && i < buffer.size(); ++byte, ++i) {
            buffer[i] = static_cast<std::uint8_t>(word & 0xFFu);
            word >>= 8;
        }
    }
}

// Two buffers and the single byte that currently makes them differ. Changing
// class is two stores rather than a fresh copy, and it is the same two stores
// either way, so the preparation cannot separate the classes by itself.
class buffers {
public:
    buffers(std::mt19937_64& rng, std::size_t bytes) : left_(bytes), right_(bytes) {
        fill_random(rng, left_);
        right_ = left_;
    }

    void differ_at(std::size_t position, bool differ) noexcept {
        right_[dirty_] = left_[dirty_];
        right_[position] = static_cast<std::uint8_t>(left_[position] ^ (differ ? 0x01u : 0x00u));
        dirty_ = position;
    }

    [[nodiscard]] const std::uint8_t* left() const noexcept { return left_.data(); }
    [[nodiscard]] const std::uint8_t* right() const noexcept { return right_.data(); }
    [[nodiscard]] std::size_t size() const noexcept { return left_.size(); }

private:
    std::vector<std::uint8_t> left_;
    std::vector<std::uint8_t> right_;
    std::size_t dirty_ = 0;
};

// The comparison a caller makes on a tag: equal, or differing somewhere the
// caller does not get to choose.
timing::result equals_equal_vs_unequal(const timing::config& cfg) {
    std::mt19937_64 setup(cfg.seed);
    buffers data(setup, buffer_bytes);

    auto prepare = [&data](std::mt19937_64& rng, int cls) {
        data.differ_at(static_cast<std::size_t>(rng() % data.size()), cls == 1);
    };
    auto run = [&data] {
        const bool same = ctsafe::equals(data.left(), data.right(), data.size());
        sink = static_cast<std::uint8_t>(sink | (same ? 1u : 0u));
    };
    return timing::measure("equals: equal vs one differing byte", cfg, prepare, run);
}

// CWE-208 itself: under memcmp a difference in the first byte costs a fraction of
// what a difference in the last one costs, and that gap is the oracle.
timing::result equals_first_vs_last_byte(const timing::config& cfg) {
    std::mt19937_64 setup(cfg.seed);
    buffers data(setup, buffer_bytes);

    auto prepare = [&data](std::mt19937_64&, int cls) {
        data.differ_at(cls == 1 ? data.size() - 1 : 0, true);
    };
    auto run = [&data] {
        const bool same = ctsafe::equals(data.left(), data.right(), data.size());
        sink = static_cast<std::uint8_t>(sink | (same ? 1u : 0u));
    };
    return timing::measure("equals: a difference in the first byte vs the last", cfg, prepare, run);
}

timing::result is_zero_zero_vs_one_bit(const timing::config& cfg) {
    std::vector<std::uint8_t> buffer(buffer_bytes, 0);
    std::size_t dirty = 0;

    auto prepare = [&buffer, &dirty](std::mt19937_64& rng, int cls) {
        const std::size_t position = static_cast<std::size_t>(rng() % buffer.size());
        buffer[dirty] = 0;
        buffer[position] = static_cast<std::uint8_t>(cls == 1 ? 0x01u : 0x00u);
        dirty = position;
    };
    auto run = [&buffer] {
        const bool zero = ctsafe::is_zero(buffer.data(), buffer.size());
        sink = static_cast<std::uint8_t>(sink | (zero ? 1u : 0u));
    };
    return timing::measure("is_zero: all zero vs a single set bit", cfg, prepare, run);
}

// The promise that a rejected copy costs the same stores as an accepted one, put
// to a clock instead of left as a claim about the source.
timing::result copy_if_mask_set_vs_clear(const timing::config& cfg) {
    std::mt19937_64 setup(cfg.seed);
    std::vector<std::uint8_t> source(buffer_bytes);
    std::vector<std::uint8_t> destination(buffer_bytes);
    fill_random(setup, source);
    fill_random(setup, destination);
    ctsafe::mask copy = 0;

    auto prepare = [&copy](std::mt19937_64&, int cls) { copy = ctsafe::mask_from_bool(cls == 1); };
    auto run = [&copy, &source, &destination] {
        ctsafe::copy_if(copy, destination.data(), source.data(), destination.size());
        sink = static_cast<std::uint8_t>(sink | destination[0]);
    };
    return timing::measure("copy_if: the mask set vs clear", cfg, prepare, run);
}

// The control. A harness that finds nothing is either measuring a constant-time
// routine or measuring nothing at all, and from outside the two look identical;
// a leak of known size tells them apart.
timing::result control_memcmp(const timing::config& cfg) {
    std::mt19937_64 setup(cfg.seed);
    buffers data(setup, buffer_bytes);

    auto prepare = [&data](std::mt19937_64&, int cls) { data.differ_at(0, cls == 1); };
    auto run = [&data] {
        const bool same = std::memcmp(data.left(), data.right(), data.size()) == 0;
        sink = static_cast<std::uint8_t>(sink | (same ? 1u : 0u));
    };
    return timing::measure("memcmp: equal vs a difference in the first byte", cfg, prepare, run);
}

struct test_case {
    timing::result (*measure)(const timing::config&);
    timing::expectation expect;
};

}  // namespace

int main(int argc, char** argv) {
    timing::config cfg;
    if (argc > 1) {
        const long rounds = std::strtol(argv[1], nullptr, 10);
        if (rounds > 0) cfg.rounds = static_cast<std::size_t>(rounds);
    }

    static const test_case cases[] = {
        {&equals_equal_vs_unequal, timing::expectation::no_difference},
        {&equals_first_vs_last_byte, timing::expectation::no_difference},
        {&is_zero_zero_vs_one_bit, timing::expectation::no_difference},
        {&copy_if_mask_set_vs_clear, timing::expectation::no_difference},
        {&control_memcmp, timing::expectation::difference},
    };
    const std::size_t count = sizeof cases / sizeof cases[0];

    std::printf("ctsafe timing: %zu rounds x %zu measurements x %zu executions, %zu-byte buffers\n\n",
                cfg.rounds, cfg.measurements, cfg.repetitions, buffer_bytes);

    int unexpected = 0;
    for (std::size_t i = 0; i < count; ++i) {
        timing::result r = cases[i].measure(cfg);
        if (!timing::ok(r, cases[i].expect)) {
            // A loaded machine produces a large t without any help from the code,
            // so a case landing on the wrong side is measured once more with a
            // different seed and only the repeat counts.
            timing::config again = cfg;
            again.seed += 1;
            r = cases[i].measure(again);
        }
        timing::print(r, cases[i].expect);
        if (!timing::ok(r, cases[i].expect)) ++unexpected;
        std::printf("\n");
    }

    std::printf("ctsafe timing: %zu cases, %d unexpected\n", count, unexpected);
    std::printf(
        "a clean run found no difference on this machine, which is not the same as there being"
        " none\n");
    return unexpected == 0 ? 0 : 1;
}
