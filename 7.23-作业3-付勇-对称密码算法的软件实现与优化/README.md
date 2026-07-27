# AES-128 软件实现与优化

本项目实现了 AES-128 基础加解密、T-table 优化、AVX2 gather/shuffle 八路并行、AES-NI 专用指令优化，以及 CTR、GCM 和 XTS 工作模式。

## 目录结构

```text
aes128-optimization-submission/
├── CMakeLists.txt
├── README.md
├── run_all.sh
├── include/
│   └── aes128.h
├── src/
│   ├── aes128_ref.c
│   ├── aes128_tables.c
│   ├── aes128_ttable.c
│   ├── aes128_avx2.c
│   ├── aes128_aesni.c
│   ├── aes128_ctr.c
│   ├── aes128_gcm.c
│   └── aes128_xts.c
├── tests/
│   ├── test_aes128.c
│   ├── test_aes128_ttable.c
│   ├── test_aes128_avx2.c
│   ├── test_aes128_aesni.c
│   ├── test_aes128_ctr.c
│   ├── test_aes128_gcm.c
│   └── test_aes128_xts.c
└── bench/
    ├── bench_aes128.c
    ├── bench_aes128_compare.c
    ├── bench_aes128_phase3.c
    ├── bench_aes128_phase4.c
    ├── bench_aes128_ctr.c
    ├── bench_aes128_gcm.c
    └── bench_aes128_xts.c
```

各目录内容如下：

- `include/`：AES-128及三种工作模式的接口声明。
- `src/`：AES基础实现、T-table、AVX2、AES-NI、CTR、GCM和XTS源码。
- `tests/`：标准测试向量、随机交叉验证、原地处理和边界条件测试。
- `bench/`：AES核心以及CTR、GCM、XTS的性能测试程序。
- `CMakeLists.txt`：CMake构建配置。
- `run_all.sh`：自动完成编译、正确性测试和基准测试。

## 编译环境

建议使用：

- GCC
- CMake
- 支持AES-NI、AVX2和PCLMULQDQ的x86-64处理器

程序会在运行时检测指令集支持情况；若硬件不支持，则自动使用软件回退路径。

## 一键编译与运行

```bash
chmod +x run_all.sh
./run_all.sh
```

## 手动编译

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

## 运行正确性测试

```bash
ctest --test-dir build --output-on-failure
```

全部测试通过时应显示：

```text
100% tests passed, 0 tests failed out of 7
```

## 运行性能测试

AES核心性能测试：

```bash
./build/bench_aes128_phase4
```

CTR模式性能测试：

```bash
./build/bench_aes128_ctr
```

GCM模式性能测试：

```bash
./build/bench_aes128_gcm
```

XTS模式性能测试：

```bash
./build/bench_aes128_xts
```

性能程序输出吞吐率、cycles/byte及相对基础实现的加速比。
