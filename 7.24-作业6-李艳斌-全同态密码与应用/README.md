# 作业6：密文卷积旋转次数分析

本项目使用 OpenFHE CKKS 实现 `4×4` 输入与 `3×3` 卷积核的密文卷积，并比较直接旋转方案与 BSGS 方案的旋转次数。

## 文件说明

```text
├── main.cpp       # 密文卷积、BSGS 优化及正确性验证
├── Makefile       # 编译和运行配置
└── README.md      # 使用说明
```

## 编译与运行

建议在 WSL/Linux 环境中运行。程序默认 OpenFHE 安装在：

```text
$HOME/opt/openfhe
```

进入项目目录：

```bash
cd "/mnt/c/Users/lenovo/Desktop/新建文件夹/大三下/创新创业/day-1/7.24-作业6-李艳斌-全同态密码与应用"
```

编译：

```bash
make
```

运行：

```bash
make run
```

重新编译：

```bash
make rebuild
```

清理编译产物：

```bash
make clean
```

如果 OpenFHE 安装在其他目录，可以指定安装路径：

```bash
make OPENFHE_PREFIX=/path/to/openfhe
make run OPENFHE_PREFIX=/path/to/openfhe
```

运行成功后，程序将输出直接方法和 BSGS 方法的旋转次数、理论最小值及正确性验证结果；末尾应显示：

```text
Minimum reached : YES
Verification    : PASS
```
