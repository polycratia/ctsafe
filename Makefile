CXX ?= c++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Werror -Iinclude -Itests
SAN ?= -fsanitize=address,undefined -fno-omit-frame-pointer -g

.PHONY: test optimized timing demo clean

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
# Takes a round count: ./build/timing 40 measures for longer.
timing:
	@mkdir -p build
	$(CXX) $(CXXFLAGS) -O2 tests/timing_ctsafe.cpp -o build/timing
	./build/timing

demo:
	@mkdir -p build
	$(CXX) $(CXXFLAGS) -O2 example/main.cpp -o build/demo
	./build/demo

clean:
	rm -rf build
