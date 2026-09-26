CXX ?= c++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Werror -Iinclude -Itests
SAN ?= -fsanitize=address,undefined -fno-omit-frame-pointer -g
ROUNDS ?=

.PHONY: test optimized timing demo check clean

test:
	@mkdir -p build
	$(CXX) $(CXXFLAGS) $(SAN) tests/test_ctsafe.cpp -o build/tests
	./build/tests

# The same suite at -O2. An erasure that only survives at -O0 is the bug this
# library exists to prevent, so the optimized build is part of the check.
optimized:
	@mkdir -p build
	$(CXX) $(CXXFLAGS) -O2 tests/test_ctsafe.cpp -o build/tests-O2
	./build/tests-O2

# Timing rather than correctness: a dudect-style comparison of the distributions
# for equal and unequal inputs. Built at -O2 and without the sanitizers, because
# both -O0 and the instrumentation would time something other than what ships.
# Exits non-zero when a case lands on the wrong side, so an unattended run fails
# instead of printing a number nobody reads.
#
#   make timing ROUNDS=40   measures for longer
timing:
	@mkdir -p build
	$(CXX) $(CXXFLAGS) -O2 tests/timing_ctsafe.cpp -o build/timing
	./build/timing $(ROUNDS)

demo:
	@mkdir -p build
	$(CXX) $(CXXFLAGS) -O2 example/main.cpp -o build/demo
	./build/demo

check: test optimized timing

clean:
	rm -rf build
