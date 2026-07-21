# Bitcoin Testnet4 Transaction and Block Parser

本项目在 Bitcoin Testnet4 上构造并广播了一笔 Legacy P2PKH 交易，并通过 Python 程序独立解析原始交易和完整区块，验证 TXID、Merkle Root、Block Hash、Proof of Work、Coinbase 交易和 witness commitment。

## 1. 项目结构

```text
bitcoin-project/
├── README.md
├── config/
│   └── openssl-legacy.cnf
├── data/
│   ├── metadata.json
│   ├── raw_funding_transaction.hex
│   ├── unsigned_transaction.hex
│   ├── raw_transaction.hex
│   └── raw_block.hex
└── src/
    ├── build_transaction.py
    ├── broadcast_and_capture.py
    ├── parse_transaction.py
    └── parse_block.py
```

## 2. 环境要求

- WSL2 / Ubuntu 22.04
- Python 3.10+
- Bitcoin Core 31.1
- OpenSSL 3.x
- Bitcoin Testnet4

解析现有交易和区块数据时，不需要运行 Bitcoin Core 节点。`parse_transaction.py` 与 `parse_block.py` 直接读取 `data/` 目录中的原始十六进制数据。

由于交易解析需要计算 `HASH160 = RIPEMD160(SHA256(data))`，运行解析程序时需要通过项目级 OpenSSL 配置启用 RIPEMD-160：

```bash
OPENSSL_CONF="$PWD/config/openssl-legacy.cnf"
```

## 3. 运行方法

### 3.1 解析实验交易

输出交易摘要和验证结果：

```bash
OPENSSL_CONF="$PWD/config/openssl-legacy.cnf" \
python3 src/parse_transaction.py --no-fields
```

输出完整逐字段解析表，包括字段偏移、长度、原始字节和解析结果：

```bash
OPENSSL_CONF="$PWD/config/openssl-legacy.cnf" \
python3 src/parse_transaction.py
```

### 3.2 解析完整区块

输出区块摘要和密码学验证结果：

```bash
OPENSSL_CONF="$PWD/config/openssl-legacy.cnf" \
python3 src/parse_block.py --no-transactions
```

输出完整区块解析结果以及区块内全部交易的偏移和大小：

```bash
OPENSSL_CONF="$PWD/config/openssl-legacy.cnf" \
python3 src/parse_block.py
```

### 3.3 重新执行链上实验

构造、签名并执行广播前检查：

```bash
python3 src/build_transaction.py
```

广播交易、等待确认，并保存原始交易和完整区块：

```bash
python3 src/broadcast_and_capture.py
```

> 当前实验使用的 Funding UTXO 已经被消费，仓库也不包含钱包私钥。重新执行链上实验时，需要准备新的 Testnet4 钱包、可花费 UTXO、收款地址和找零地址，并更新 `data/metadata.json`。

## 4. 文件说明

| 文件 | 作用 |
|---|---|
| `src/build_transaction.py` | 检查 Funding UTXO，构造并签名 Legacy P2PKH 交易，并调用 `testmempoolaccept` 完成广播前检查 |
| `src/broadcast_and_capture.py` | 广播已签名交易，等待区块确认，保存原始交易和完整原始区块 |
| `src/parse_transaction.py` | 独立逐字节解析交易，解析 P2PKH 脚本和 DER 签名，并重算 TXID、WTXID |
| `src/parse_block.py` | 独立解析完整区块，验证 Merkle Root、Block Hash、PoW、Coinbase 和 witness commitment |
| `config/openssl-legacy.cnf` | 项目级 OpenSSL 配置，用于启用 RIPEMD-160 |
| `data/metadata.json` | 保存网络、地址、金额、交易和区块元数据 |
| `data/raw_funding_transaction.hex` | 水龙头 Funding Transaction 的原始序列化数据 |
| `data/unsigned_transaction.hex` | 未签名实验交易的原始序列化数据 |
| `data/raw_transaction.hex` | 已签名并上链的实验交易原始序列化数据 |
| `data/raw_block.hex` | 包含实验交易的完整原始区块 |
