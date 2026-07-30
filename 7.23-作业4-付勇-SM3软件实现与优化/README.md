# 作业4：SM3 软件实现与优化

本实验基于 SIMD 寄存器和通用寄存器混合使用的 SM3 优化版本，覆盖 ARM64 和 x86 两类处理器架构。

主要内容包括：

- SM3 标量参考实现；
- ARM64 NEON 与汇编优化实现；
- x86 AVX2 八路并行实现；
- x86 AVX-512 十六路并行实现；
- 运行时指令集检测与后端自动分发；
- 正确性验证和性能测试。

## 目录结构

```text
.
├── sm3_c/       # SM3 标量参考实现
├── sm3_arm/     # ARM64 NEON 与汇编实现
├── sm3_x86/     # x86 AVX2、AVX-512 实现
└── 报告.pdf     # 实验报告
```

## x86 编译与测试

```bash
cd sm3_x86

make clean
make -j"$(nproc)" all

make test
make verify-openssl
make sanitize
make asm-check
```

性能测试：

```bash
taskset -c 2 ./sm3_x86_bench
```

## 实验结果

x86 AVX2 实现已通过：

- 边界长度与随机差分测试；
- 149 组 OpenSSL SM3 差分验证；
- AddressSanitizer 与 UndefinedBehaviorSanitizer 检查；
- YMM、ZMM 与通用寄存器反汇编验证。

在 Intel Core i7-13700H 平台上，AVX2 相对于标量实现的加速比约为 6.3～6.7 倍。

ARM64 部分的具体编译与测试方法见 `sm3_arm/README.md`。
