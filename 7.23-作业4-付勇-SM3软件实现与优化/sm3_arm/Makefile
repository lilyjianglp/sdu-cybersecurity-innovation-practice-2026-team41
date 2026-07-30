# SM3 project Makefile

CC ?= gcc
AR ?= ar
ARFLAGS ?= rcs

CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wshadow
CPPFLAGS ?=
ASFLAGS ?=
LDFLAGS ?=

PREFIX ?= /usr/local
BINDIR ?= bin

C_DIR := ../sm3_c
ARM_DIR := .

IMPL ?= ref
BENCH_ARGS ?=

BUILD_DIR := build/$(IMPL)

SM3_SRC := $(C_DIR)/sm3.c
SM3_ARM64_NEON_SRC := $(ARM_DIR)/sm3_arm64_neon.c
SM3_ARM64_ASM_SRC := $(ARM_DIR)/sm3_arm64.S
TEST_SRC := $(C_DIR)/sm3_test.c
BENCH_SRC := $(C_DIR)/sm3_bench.c

SM3_OBJ := $(BUILD_DIR)/sm3.o
SM3_ARM64_NEON_OBJ := $(BUILD_DIR)/sm3_arm64_neon.o
SM3_ARM64_ASM_OBJ := $(BUILD_DIR)/sm3_arm64.o
TEST_OBJ := $(BUILD_DIR)/sm3_test.o
BENCH_OBJ := $(BUILD_DIR)/sm3_bench.o

LIB := libsm3.a
BIN := sm3_test
BENCH_BIN := sm3_bench
REF_BENCH_BIN := sm3_bench_ref
ARM64_NEON_BENCH_BIN := sm3_bench_arm64_neon
ARM64_ASM_BENCH_BIN := sm3_bench_arm64_asm

INCLUDES := -I$(C_DIR)

ifeq ($(IMPL),ref)
    IMPL_CPPFLAGS :=
    BACKEND_OBJ :=
else ifeq ($(IMPL),arm64_neon)
    IMPL_CPPFLAGS := -DSM3_USE_ARM64_NEON
    BACKEND_OBJ := $(SM3_ARM64_NEON_OBJ)
else ifeq ($(IMPL),arm64_asm)
    IMPL_CPPFLAGS := -DSM3_USE_ARM64_ASM
    BACKEND_OBJ := $(SM3_ARM64_ASM_OBJ)
else
    $(error Unsupported IMPL="$(IMPL)". Use IMPL=ref, IMPL=arm64_neon, or IMPL=arm64_asm)
endif

LIB_OBJS := $(SM3_OBJ) $(BACKEND_OBJ)
BIN_OBJS := $(LIB_OBJS) $(TEST_OBJ)
BENCH_OBJS := $(LIB_OBJS) $(BENCH_OBJ)

.PHONY: all test bench bench-compare clean install uninstall info

all: $(BIN)

$(BUILD_DIR):
	mkdir -p $@

$(SM3_OBJ): $(SM3_SRC) \
            $(C_DIR)/sm3.h \
            $(C_DIR)/sm3_internal.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(IMPL_CPPFLAGS) $(CFLAGS) $(INCLUDES) \
		-c $< -o $@

$(SM3_ARM64_NEON_OBJ): $(SM3_ARM64_NEON_SRC) \
                       $(C_DIR)/sm3.h \
                       $(C_DIR)/sm3_internal.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(IMPL_CPPFLAGS) $(CFLAGS) $(INCLUDES) \
		-c $< -o $@

$(SM3_ARM64_ASM_OBJ): $(SM3_ARM64_ASM_SRC) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(IMPL_CPPFLAGS) $(ASFLAGS) $(INCLUDES) \
		-c $< -o $@

$(TEST_OBJ): $(TEST_SRC) $(C_DIR)/sm3.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(IMPL_CPPFLAGS) $(CFLAGS) $(INCLUDES) \
		-c $< -o $@

$(BENCH_OBJ): $(BENCH_SRC) $(C_DIR)/sm3.h | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(IMPL_CPPFLAGS) $(CFLAGS) $(INCLUDES) \
		-c $< -o $@

$(LIB): $(LIB_OBJS)
	rm -f $@
	$(AR) $(ARFLAGS) $@ $^

$(BIN): $(BIN_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BENCH_BIN): $(BENCH_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test: $(BIN)
	./$(BIN)

bench: $(BENCH_BIN)
	./$(BENCH_BIN) $(BENCH_ARGS)

bench-compare:
	$(MAKE) IMPL=ref BENCH_BIN=$(REF_BENCH_BIN) $(REF_BENCH_BIN)
	$(MAKE) IMPL=arm64_neon BENCH_BIN=$(ARM64_NEON_BENCH_BIN) \
		$(ARM64_NEON_BENCH_BIN)
	$(MAKE) IMPL=arm64_asm BENCH_BIN=$(ARM64_ASM_BENCH_BIN) \
		$(ARM64_ASM_BENCH_BIN)
	@echo
	@echo "===== Reference implementation ====="
	./$(REF_BENCH_BIN) $(BENCH_ARGS)
	@echo
	@echo "===== ARM64 NEON implementation ====="
	./$(ARM64_NEON_BENCH_BIN) $(BENCH_ARGS)
	@echo
	@echo "===== ARM64 assembly implementation ====="
	./$(ARM64_ASM_BENCH_BIN) $(BENCH_ARGS)

info:
	@echo "Implementation: $(IMPL)"
	@echo "Compiler:       $(CC)"
	@echo "Build directory: $(BUILD_DIR)"
	@echo "Objects:        $(BIN_OBJS)"

clean:
	rm -rf build
	rm -f $(LIB) $(BIN) $(BENCH_BIN) \
		$(REF_BENCH_BIN) $(ARM64_NEON_BENCH_BIN) \
		$(ARM64_ASM_BENCH_BIN)

install: $(BIN)
	install -d $(DESTDIR)$(PREFIX)/$(BINDIR)
	install -m 755 $(BIN) $(DESTDIR)$(PREFIX)/$(BINDIR)/$(BIN)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/$(BINDIR)/$(BIN)
