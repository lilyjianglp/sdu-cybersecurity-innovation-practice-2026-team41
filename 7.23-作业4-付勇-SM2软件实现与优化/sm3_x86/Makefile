CC ?= gcc
C_DIR := ../sm3_c
BUILD_DIR := build

CPPFLAGS := -I. -I$(C_DIR)
COMMON_CFLAGS := -std=c11 -O3 -Wall -Wextra -Wpedantic -Wshadow -Wconversion \
                 -fno-strict-aliasing
BASE_CFLAGS := $(COMMON_CFLAGS)
AVX2_CFLAGS := $(COMMON_CFLAGS) -mavx2
AVX512_CFLAGS := $(COMMON_CFLAGS) -mavx512f
LDFLAGS ?=

SCALAR_OBJ := $(BUILD_DIR)/sm3.o
DISPATCH_OBJ := $(BUILD_DIR)/sm3_dispatch.o
AVX2_OBJ := $(BUILD_DIR)/sm3_avx2.o
AVX512_OBJ := $(BUILD_DIR)/sm3_avx512.o
TEST_OBJ := $(BUILD_DIR)/sm3_x86_test.o
BENCH_OBJ := $(BUILD_DIR)/sm3_x86_bench.o
CLI_OBJ := $(BUILD_DIR)/sm3_x86_cli.o
CORE_OBJS := $(SCALAR_OBJ) $(DISPATCH_OBJ) $(AVX2_OBJ) $(AVX512_OBJ)

TEST_BIN := sm3_x86_test
BENCH_BIN := sm3_x86_bench
CLI_BIN := sm3_x86_cli

.PHONY: all test bench verify-openssl sanitize asm-check clean info

all: $(TEST_BIN) $(BENCH_BIN) $(CLI_BIN)

$(BUILD_DIR):
	mkdir -p $@

$(SCALAR_OBJ): $(C_DIR)/sm3.c $(C_DIR)/sm3.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) -c $< -o $@

$(DISPATCH_OBJ): sm3_dispatch.c sm3_x86.h $(C_DIR)/sm3.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) -c $< -o $@

$(AVX2_OBJ): sm3_avx2.c sm3_x86.h $(C_DIR)/sm3.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(AVX2_CFLAGS) -c $< -o $@

$(AVX512_OBJ): sm3_avx512.c sm3_x86.h $(C_DIR)/sm3.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(AVX512_CFLAGS) -c $< -o $@

$(TEST_OBJ): sm3_x86_test.c sm3_x86.h $(C_DIR)/sm3.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) -c $< -o $@

$(BENCH_OBJ): sm3_x86_bench.c sm3_x86.h $(C_DIR)/sm3.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) -c $< -o $@


$(CLI_OBJ): sm3_x86_cli.c sm3_x86.h $(C_DIR)/sm3.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) -c $< -o $@

$(TEST_BIN): $(CORE_OBJS) $(TEST_OBJ)
	$(CC) $^ -o $@ $(LDFLAGS)

$(BENCH_BIN): $(CORE_OBJS) $(BENCH_OBJ)
	$(CC) $^ -o $@ $(LDFLAGS)

$(CLI_BIN): $(CORE_OBJS) $(CLI_OBJ)
	$(CC) $^ -o $@ $(LDFLAGS)

test: $(TEST_BIN)
	./$(TEST_BIN)

bench: $(BENCH_BIN)
	./$(BENCH_BIN)

verify-openssl: $(CLI_BIN) $(TEST_BIN)
	./verify_openssl.py

sanitize: clean
	$(MAKE) COMMON_CFLAGS='-std=c11 -O1 -g -Wall -Wextra -Wpedantic -Wshadow -fno-omit-frame-pointer -fsanitize=address,undefined' LDFLAGS='-fsanitize=address,undefined' test

asm-check: $(AVX2_OBJ) $(AVX512_OBJ)
	objdump -d -Mintel $(AVX2_OBJ) > $(BUILD_DIR)/sm3_avx2.asm
	objdump -d -Mintel $(AVX512_OBJ) > $(BUILD_DIR)/sm3_avx512.asm
	@echo 'AVX2 YMM instructions:'
	@grep -E -m 12 'ymm|vpaddd|vpxor|vpslld|vpsrld' $(BUILD_DIR)/sm3_avx2.asm || true
	@echo 'AVX-512 ZMM/mask instructions:'
	@grep -E -m 12 'zmm|vpaddd|vpxord|k[0-7]' $(BUILD_DIR)/sm3_avx512.asm || true

info:
	@echo "CC: $(CC)"
	@$(CC) --version | head -n 1
	@echo "AVX2 flags: $(AVX2_CFLAGS)"
	@echo "AVX-512 flags: $(AVX512_CFLAGS)"

clean:
	rm -rf $(BUILD_DIR) $(TEST_BIN) $(BENCH_BIN) $(CLI_BIN)
