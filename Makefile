CXX ?= c++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Werror -Iinclude -Itests
SAN ?= -fsanitize=address,undefined -fno-omit-frame-pointer -g
OPT_LEVELS ?= -O0 -O2 -O3
ROUNDS ?=
SUITES ?= tests/test_ctsafe.cpp tests/test_less_than.cpp

.PHONY: test matrix disasm timing demo check clean

# Twice: the rows this platform selects, and the rows a compiler this header
# does not recognise would get. CTSAFE_PORTABLE forces every fallback — no
# platform erase routine, no compiler barrier — so the weakest build the library
# ships is run rather than described.
test:
	@mkdir -p build
	@for suite in $(SUITES); do \
		name=`basename $$suite .cpp`; \
		$(CXX) $(CXXFLAGS) $(SAN) $$suite -o build/$$name || exit 1; \
		./build/$$name || exit 1; \
		$(CXX) $(CXXFLAGS) $(SAN) -DCTSAFE_PORTABLE $$suite -o build/$$name-portable || exit 1; \
		./build/$$name-portable || exit 1; \
	done

# The same suites at every optimisation level. An erasure that only survives at
# -O0 is the bug this library exists to prevent, so -O2 and -O3 are part of the
# check rather than something a user finds out later.
#
#   make matrix OPT_LEVELS="-O0 -O1 -O2 -O3 -Os"
matrix:
	@mkdir -p build
	@for level in $(OPT_LEVELS); do \
		echo "ctsafe: tests at $$level"; \
		for suite in $(SUITES); do \
			name=`basename $$suite .cpp`; \
			$(CXX) $(CXXFLAGS) $$level $$suite -o build/$$name$$level || exit 1; \
			./build/$$name$$level || exit 1; \
		done; \
		echo; \
	done

# What the suites above cannot see: a test reads the zeroes back, and a compiler
# may emit the store for the function that reads it while deleting it where
# nothing does. This one reads the instructions.
disasm:
	@mkdir -p build
	@CXX="$(CXX)" CXXFLAGS="$(CXXFLAGS)" OPT_LEVELS="$(OPT_LEVELS)" sh tools/erase_disasm.sh

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

check: test matrix disasm timing

clean:
	rm -rf build
