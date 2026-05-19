CXX      := g++
CXXFLAGS := -std=c++20 -O3 -Wall -Wextra -Wpedantic -march=native

INCLUDES := -Icrypto

LIBS_CRYPTO    := -lcrypto
LIBS_TEST      := -lgtest -lgtest_main -pthread
LIBS_BENCHMARK := -lbenchmark -pthread

SRC_DIR        := crypto
BENCHMARK_DIR  := benchmark/crypto
TEST_DIR       := tests/crypto
BUILD_DIR      := build

LIB_OBJ        := $(BUILD_DIR)/ml_kem.o
TEST_BINARY    := $(BUILD_DIR)/ml_kem_test
BENCH_BINARY   := $(BUILD_DIR)/ml_kem_bench

HPP  := $(shell find . -name "*.hpp" -o -name "*.cpp")

.PHONY: all test bench clean format format-hpp/cpp

all: $(TEST_BINARY) $(BENCH_BINARY)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(LIB_OBJ): $(SRC_DIR)/ml_kem.cpp $(SRC_DIR)/ml_kem.hpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

$(TEST_BINARY): $(TEST_DIR)/ml_kem_test.cpp $(LIB_OBJ)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $^ -o $@ $(LIBS_CRYPTO) $(LIBS_TEST)

$(BENCH_BINARY): $(BENCHMARK_DIR)/ml_kem_benchmark.cpp $(LIB_OBJ)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $^ -o $@ $(LIBS_CRYPTO) $(LIBS_BENCHMARK)

test: $(TEST_BINARY)
	./$(TEST_BINARY)

bench: $(BENCH_BINARY)
	./$(BENCH_BINARY)

clean:
	rm -rf $(BUILD_DIR)

format-hpp/cpp:
	@if [ -z "$(HPP)" ]; then \
		echo "[!] Files not found"; \
	else \
		clang-format -i $(HPP); \
	fi
