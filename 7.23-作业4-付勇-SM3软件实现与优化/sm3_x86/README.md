# SM3 x86 SIMD 实现

## 1. 正确性验证

### 1.1 标准向量、边界和随机差分

```bash
make test
```


### 1.2 与 OpenSSL 差分

```bash
make verify-openssl
```

脚本生成 149 个固定边界和随机文件，通过自动分发版本计算摘要，再与：

```bash
openssl dgst -sm3 -binary FILE
```

逐字节比较。

### 1.3 内存和未定义行为检查

```bash
make sanitize
```

使用 AddressSanitizer 和 UndefinedBehaviorSanitizer。

## 2. 检查是否真的生成 SIMD 指令

```bash
make clean
make -j"$(nproc)" all
make asm-check
```

手工检查：

```bash
grep -E 'ymm|vpaddd|vpxor|vpslld|vpsrld' build/sm3_avx2.asm | head -n 30
grep -E 'zmm|vpaddd|vpxord|vprold|k[0-7]' build/sm3_avx512.asm | head -n 30
```

## 3. 性能测试

快速测试：

```bash
./sm3_x86_bench 1024 256
```


完整测试：

```bash
taskset -c 2 ./sm3_x86_bench
```


