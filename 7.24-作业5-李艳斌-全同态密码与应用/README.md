# OpenFHE CKKS 密文卷积

本项目使用 OpenFHE 的 CKKS 方案，实现单输入、单输出的密文二维卷积：

- 输入：`4 × 4`
- 卷积核：`3 × 3`
- 步长：`1`
- 填充：`0`
- 输出：`2 × 2`

程序通过密文旋转、密文与明文逐槽乘法及密文加法完成卷积，并将解密结果与明文卷积结果比较。最大绝对误差小于阈值时输出 `PASS`。

## 项目结构

```text
作业5/
├── main.cpp    # 密文卷积、明文对照计算及正确性验证
├── Makefile    # 编译、运行和清理命令
├── README.md   # 项目说明
└── report.pdf  # 实验报告
```

`main.cpp` 的主要组成：

- `PlainConv2D`：计算明文卷积，作为正确结果；
- `CreateCKKSContext`：配置 CKKS 参数并创建加密上下文；
- `EncryptedConv2D`：执行旋转、逐槽乘法和累加；
- `DecryptSlots`、`ExtractOutput`：解密并提取输出槽位；
- `MaxAbsoluteError`：计算最大绝对误差；
- `main`：完成密钥生成、加密、计算、解密与验证。

## 编译与运行

建议在 WSL/Linux 环境中运行。默认 OpenFHE 安装目录为：

```text
$HOME/opt/openfhe
```

进入项目目录：

```bash
cd "/mnt/c/Users/lenovo/Desktop/新建文件夹/大三下/创新创业/day-1/作业5"
```

编译：

```bash
make
```

运行：

```bash
make run
```

重新编译并运行：

```bash
make rebuild
make run
```

清理编译产物：

```bash
make clean
```

如果 OpenFHE 安装在其他位置，可在编译时指定：

```bash
make OPENFHE_PREFIX=/path/to/openfhe
```

程序正确运行时，末尾将显示：

```text
Verification           : PASS
```
