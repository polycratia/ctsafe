// A dudect-style timing harness. It does not prove constant time; it tries to
// disprove it, and reports how hard it tried.
//
// The shape is from Reparaz, Balasch and Verbauwhede, "dude, is my code constant
// time?" (2016): time one operation over two classes of input, draw the class at
// random before every measurement so that drift cannot line up with one class,
// crop the slow tail where the scheduler lives at many percentiles, and apply
// Welch's t-test to what is left. The paper's threshold is |t| > 10, which is
// also why cropping at a hundred points is not a multiple-comparisons problem:
// 10 is far outside the range noise reaches.
#pragma once

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <random>
#include <utility>
#include <vector>

namespace timing {

/// What a case asserts about the two distributions.
enum class expectation {
    no_difference,  ///< The operation under test must not separate the classes.
    difference,     ///< A control: a known leak, which the harness has to catch.
};

/// Mean and variance per class by Welford's update — the naive sum of squares
/// loses precision at the sample counts this needs — and the Welch statistic.
class welch {
public:
    static constexpr double enough = 100.0;

    void push(double value, int cls) noexcept {
        double& n = n_[cls];
        double& mean = mean_[cls];
        n += 1.0;
        const double delta = value - mean;
        mean += delta / n;
        m2_[cls] += delta * (value - mean);
    }

    [[nodiscard]] double samples(int cls) const noexcept { return n_[cls]; }

    /// Zero until both classes hold enough, so a crop that kept three
    /// measurements cannot contribute the largest t in the run.
    [[nodiscard]] double t() const noexcept {
        if (n_[0] < enough || n_[1] < enough) return 0.0;
        const double variance_0 = m2_[0] / (n_[0] - 1.0);
        const double variance_1 = m2_[1] / (n_[1] - 1.0);
        const double spread = std::sqrt(variance_0 / n_[0] + variance_1 / n_[1]);
        if (!(spread > 0.0)) return 0.0;
        return (mean_[0] - mean_[1]) / spread;
    }

private:
    double n_[2] = {0.0, 0.0};
    double mean_[2] = {0.0, 0.0};
    double m2_[2] = {0.0, 0.0};
};

struct config {
    std::size_t calibration = 5000;    ///< Measurements used only to place the crops.
    std::size_t measurements = 20000;  ///< Measurements per round.
    std::size_t rounds = 6;            ///< Rounds, stopping early once decided.
    std::size_t repetitions = 4;       ///< Executions inside one timed region.
    std::size_t crops = 100;           ///< Percentile cuts, plus the uncropped test.
    double fail_at = 10.0;             ///< |t| above this is a difference.
    double watch_at = 5.0;             ///< |t| above this is worth a longer run.
    std::uint64_t seed = 20260101;
};

struct result {
    const char* name = "";
    double t = 0.0;
    std::size_t samples = 0;
    std::size_t rounds = 0;
    std::size_t crops = 0;
    double fail_at = 10.0;
    double watch_at = 5.0;
};

/// Where to cut the tail. The cuts thicken towards the top of the distribution,
/// because that is where a preempted measurement lands and where the difference
/// being looked for does not.
[[nodiscard]] inline std::vector<double> crop_thresholds(std::vector<double> sample,
                                                        std::size_t count) {
    std::vector<double> thresholds;
    if (sample.empty() || count == 0) return thresholds;

    std::sort(sample.begin(), sample.end());
    thresholds.reserve(count);
    for (std::size_t i = 1; i <= count; ++i) {
        const double quantile =
            1.0 - std::pow(0.5, 10.0 * static_cast<double>(i) / static_cast<double>(count));
        std::size_t index =
            static_cast<std::size_t>(quantile * static_cast<double>(sample.size() - 1));
        if (index >= sample.size()) index = sample.size() - 1;
        thresholds.push_back(sample[index]);
    }
    return thresholds;
}

/// One timed region. The repetitions are there because a single call over a small
/// buffer is shorter than the clock can resolve; both classes are batched the
/// same way, so the comparison between them still holds.
template <typename Operation>
[[nodiscard]] inline double timed(Operation& run, std::size_t repetitions) {
    const auto start = std::chrono::steady_clock::now();
    for (std::size_t i = 0; i < repetitions; ++i) run();
    const auto end = std::chrono::steady_clock::now();
    return std::chrono::duration<double, std::nano>(end - start).count();
}

[[nodiscard]] inline double largest(const std::vector<welch>& tests) noexcept {
    double best = 0.0;
    for (const welch& test : tests) {
        const double t = test.t();
        if (std::fabs(t) > std::fabs(best)) best = t;
    }
    return best;
}

/// Measure one case. `prepare(rng, cls)` sets the inputs up for class 0 or 1 and
/// is not timed; `run()` is the operation, and must keep its own answer alive.
template <typename Prepare, typename Operation>
[[nodiscard]] result measure(const char* name, const config& cfg, Prepare prepare, Operation run) {
    std::mt19937_64 rng(cfg.seed ^ 0x9E3779B97F4A7C15ull);

    std::vector<double> calibration;
    calibration.reserve(cfg.calibration);
    for (std::size_t i = 0; i < cfg.calibration; ++i) {
        const int cls = static_cast<int>(rng() & 1u);
        prepare(rng, cls);
        calibration.push_back(timed(run, cfg.repetitions));
    }

    const std::vector<double> crops = crop_thresholds(std::move(calibration), cfg.crops);
    std::vector<welch> tests(crops.size() + 1);

    result out;
    out.name = name;
    out.crops = crops.size();
    out.fail_at = cfg.fail_at;
    out.watch_at = cfg.watch_at;

    for (std::size_t round = 0; round < cfg.rounds; ++round) {
        for (std::size_t i = 0; i < cfg.measurements; ++i) {
            const int cls = static_cast<int>(rng() & 1u);
            prepare(rng, cls);
            const double elapsed = timed(run, cfg.repetitions);

            tests[0].push(elapsed, cls);
            for (std::size_t k = 0; k < crops.size(); ++k) {
                if (elapsed < crops[k]) tests[k + 1].push(elapsed, cls);
            }
        }

        out.t = largest(tests);
        out.samples = static_cast<std::size_t>(tests[0].samples(0) + tests[0].samples(1));
        out.rounds = round + 1;
        if (std::fabs(out.t) > cfg.fail_at) break;  // decided; more rounds add nothing
    }
    return out;
}

[[nodiscard]] inline bool difference_found(const result& r) noexcept {
    return std::fabs(r.t) > r.fail_at;
}

/// A case is fine when what was found is what it asserted: no difference for the
/// routines, a difference for the control that exists to show the clock works.
[[nodiscard]] inline bool ok(const result& r, expectation expect) noexcept {
    return difference_found(r) == (expect == expectation::difference);
}

inline void print(const result& r, expectation expect) {
    std::printf("%s%s\n", expect == expectation::difference ? "control - " : "", r.name);
    std::printf("  max |t| = %.2f across %zu crops, %zu measurements, %zu rounds\n",
                std::fabs(r.t), r.crops + 1, r.samples, r.rounds);

    if (expect == expectation::difference) {
        std::printf(difference_found(r)
                        ? "  difference found, which is what this case is for\n"
                        : "  NO DIFFERENCE FOUND - the harness is blind here, so nothing"
                          " above is evidence\n");
        return;
    }

    if (difference_found(r)) {
        std::printf("  DIFFERENCE FOUND at |t| > %.0f - this is not constant time\n", r.fail_at);
    } else if (std::fabs(r.t) > r.watch_at) {
        std::printf("  no difference at |t| > %.0f, but above %.0f: worth a longer run\n", r.fail_at,
                    r.watch_at);
    } else {
        std::printf("  no difference at |t| > %.0f - consistent with constant time\n", r.fail_at);
    }
}

}  // namespace timing
