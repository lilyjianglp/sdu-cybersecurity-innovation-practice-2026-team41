# SM3 ARM64 编译说明

在当前 `sm3_arm` 目录执行以下命令。

```bash
# 参考 C 实现
make IMPL=ref test

# ARM64 NEON 实现
make IMPL=arm64_neon test

# ARM64 手写汇编实现
make IMPL=arm64_asm test

# 比较三种实现的性能
make bench-compare

# 指定消息大小（字节）和测试总量（MB）
make bench-compare BENCH_ARGS="4096 256"

# 清理构建产物
make clean
```