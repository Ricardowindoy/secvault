# secvault 实验总结报告

> 实验平台：Radxa Cubie A7Z（全志 A733 / sun60iw2p1），aarch64，Debian 11，内核 5.15.147-8-a733（BSP）
> CPU：2×Cortex-A76 @2.0GHz（大核）+ 6×Cortex-A55 @1.79GHz（小核），8GB LPDDR4X
> 工具：Go 1.26.6、OpenSSL 1.1.1w、gcc 10.2.1、klauspost/reedsolomon v1.14.2
> 实验周期：2026-08-30 ～ 09-02；全部数字为实测（标注"推算"者除外）

---

## 1. 硬件加速资源盘点（结论）

| 层面 | 状态 | 说明 |
|---|---|---|
| CPU 加密指令（ARMv8 Crypto Ext，8 核全有） | ✅ 生效 | `aes`/`sha1`/`sha2`/`pmull`/`crc32`；**无** sha512/sha3/sm3/sm4 |
| SoC 独立加密引擎（sun8i-ce） | ❌ 未启用 | 内核未编译，且只支持 AES/SHA/RC4/CRC 类，无 RS |
| NPU（VIP9000 3TOPS） | ❌ 对本任务不可用 | 语义不兼容（NN 图执行器 vs GF 纠删码）；且实测 `/dev/vipcore` 设备节点已消失、用户态库缺 |
| GPU（Mali） | ❌ 不存在 | 设备树未启用，clinfo 0 平台 |
| NEON SIMD | ✅ 唯一可挖方向 | klauspost arm64 classic 路径已用 vtbl；leopard 路径纯 Go 单线程 |

**内核侧**：`CONFIG_CRYPTO_AES_ARM64_CE / SHA1_ARM64_CE / SHA2_ARM64_CE / GHASH_ARM64_CE` 全部 `not set` → 内核 Crypto API 全软件（用户态不受影响，OpenSSL/Go 自带 ARMv8 汇编）。

## 2. 加密算法速度表（实测）

### 2.1 用户态（OpenSSL 1.1.1w，大核 A76 @2GHz，16KB 块）

| 算法 | MB/s | 硬件指令 |
|---|---:|---|
| AES-128-GCM | **1708** | ✅ AES+PMULL |
| AES-128-CBC | 1610 | ✅ |
| AES-256-GCM | 1421 | ✅ |
| AES-192-CBC | 1326 | ✅ |
| SHA-256 | 1252 | ✅ SHA2 |
| SHA-1 | 1219 | ✅ SHA1 |
| AES-256-CBC | 1141 | ✅ |
| ChaCha20-Poly1305 | 551 | ❌（NEON 向量） |
| SHA-512 | 331 | ❌ 纯软件（sha2 指令只覆盖 256 位族） |

小核（A55）：AES-256-GCM 658、SHA-256 758（为大核的 46-61%）。
分块效应：AES-256-CBC 16B→1064MB/s 陡升，8KB 后饱和；SHA-256 16B 仅 56MB/s。

### 2.2 内核 Crypto API（自写 AF_ALG 基准，256KB 块）

| 算法 | 驱动 | MB/s | 备注 |
|---|---|---:|---|
| crc32c | lib 层 | **7473~8915** | 唯一走硬件指令（CRC32）的内核算法 |
| xchacha20 / chacha20 | -neon | ~500 | NEON 向量 |
| md5 | generic | 323 | |
| sha384 / sha512 | generic | 220 | |
| sha1 | generic | 198 | |
| sha256 / hmac(sha256) | generic | 173 | |
| ecb/cbc/ctr(aes) | generic | 126~133 | dm-crypt 实际性能即此 |
| ecb(des3_ede) | generic | 26 | |

用户态 vs 内核态 AES-256-CBC：1141 vs 128 MB/s（**9 倍差**）——内核侧无任何硬件加速。

### 2.3 AF_ALG 平台坑（BSP 内核实测）

1. 密钥必须设在 **parent socket**（accept 后设报 EOPNOTSUPP）；
2. 发 `ALG_SET_OP` cmsg 直接 EINVAL（默认方向即加密）；
3. 哈希 bind 类型名是 `hash` 而非 `ahash`（6.2 才有别名）；IV cmsg 头为 4 字节 u32；
4. skcipher 模板懒实例化，首次按名 bind 才注册；
5. `openssl speed -engine afalg` 结果不可信（异步引擎测量失真，报 10.5GB/s 假值）。

## 3. GF(256) 与纠删码基准（gfbench/，纯内存无业务）

### 3.1 原语吞吐（大核）

| 原语 | 吞吐 | 备注 |
|---|---:|---|
| CRC32C | 8.88 GB/s | 硬件指令 |
| memcpy | 5.12 GB/s | 内存带宽上限参考 |
| GF muladd（NEON vtbl，工作集 ≤512KB） | 4.75~4.87 GB/s | L2 内不衰减 |
| GF muladd（2MB） | 3.28 GB/s | **-33%**（L2=512KB 溢出） |
| GF muladd（16MB） | 2.29 GB/s | **-53%** |
| XOR | 2.18 GB/s | |
| SHA-256 | 1.25 GB/s | |
| GF 乘加（klauspost 库内实测） | ~10.8 GB/s | 多核聚合 |
| leopard 纯 Go（secvault 块内配置） | ~0.12 GB/s | 单线程 |

**排序：CRC32C > memcpy > vtbl-muladd > XOR > SHA-256 ≫ GF-leopard——GF 乘法比便宜原语慢 20-70 倍，这是所有纠删码性能问题的根源。**

### 3.2 纠删码配置扫描（klauspost，数据侧吞吐）

| 配置 | 大核 | 小核 | 比值 |
|---|---:|---:|---:|
| RS(16,4) 1MB shard | **2700** | 233 | 11.6× |
| RS(64,16) 256KB | 446 | — | |
| RS(128,64) 256KB | 164.5 | **15.6** | **10.5×** |
| leopard RS(256,128) 4KB | 133.2 | 40.2 | 3.3× |
| leopard RS(256,128) 256KB | 110.8 | — | shard 大反而慢（L2） |
| cgo 自研 vtbl RS(16,4) | 862 | 233 | 3.7× |
| cgo 自研 vtbl RS(128,64) | 70.8 | — | 输给 klauspost 2.3× |

**核心规律**：数据侧吞吐 ≈ GF乘加带宽 X ÷ 校验数 m（O(k·m) 码）；leopard 是 FFT 算法在 k=256 体制下反超 O(k·m)。k=16 时 2.7GB/s vs k=256 时 133MB/s = **20 倍差距**（k+m 分片过多是第一大坑）。

### 3.3 系统级坑位核对（对照 A76 嵌入式坑位清单）

| 坑 | 裁定 |
|---|---|
| L2(512KB) 溢出 | ✅ 实锤：muladd 4.9→2.3GB/s |
| 编码线程漂小核 | ✅ 实锤：3-10.5× 崩塌（RS(128,64) 最惨 15.6MB/s） |
| 温控降频 | ❌ 未命中：基准期 avg 2.0GHz、最高 43.6°C |
| governor=ondemand | ⚠️ 部分：升频迟滞（min 1.2GHz），avg 拉满 |
| 查表 vs PMULL 前提 | ⚠️ 修正：GF(256) 常系数乘的正确 NEON 指令是 **vtbl**（SIMD 查表），不是 pmull（那是 GF(2^128)/GCM 的工具）；"150-240MB/s 合理 PMULLW 预期"对应小 k 配置，实测 RS(16,4) 轻松 2.7GB/s（超预期 10×+） |

## 4. 视频加密方案选型结论

威胁模型：防 bit 反转（必须 AEAD 认证 + 可恢复纠错），无副本，月度人工巡检。

| 方案 | 编码吞吐 | 防 bit 反转 | 裁决 |
|---|---:|---|---|
| AES-GCM 单独 | ~1400 | ❌ 检测不恢复 | 不够 |
| CBC/CTR/XTS 单独 | — | ❌ 可定向篡改 | 禁用 |
| 分块 GCM + 双层 RS（**方案 C**） | 59 | ✅ 块内 128 shard + 组内 64 blob | **采纳** |
| 混合（XOR 快修 + 文件级 RS） | 100-130 推算 | 中 | v3 候选 |
| 复制型（m=k） | 200-250 推算 | 强（另一份好即可） | v3 候选 |
| NEON PMULL 手写内核 | 60-100 推算 | 同 C | 已证伪性价比 |
| 无纠错纯校验 | ~500 | ❌ | 仅可重拉场景 |

关键设计决策：
- **分层修复粒度**：块内 RS(256,128) 修零星损坏（KB 级 I/O），文件级 RS(128,64) 兜整块死亡（MB 级 I/O）——分层不是容错叠加而是修复成本分层；
- ECC 套密文外、GCM tag 纳入 ECC 保护域、重建后必过 GCM 终审（信任锚唯一）；
- sha256 做块内 shard tag（评估过 CRC32C 替换，省 1.2ms/块，未采纳）。

## 5. secvault 库（最终形态 v2）

- 位置：`p91mcp/secvault`（纯 Go 跨架构，arm64 写的容器可在 amd64 上 scrub/重建）
- 格式 v2：组内 **parity 在前**（`[64 parity][128 数据]`/组）——parity 偏移组内局部可算，数据写与 parity 计算位置解耦（无屏障布局，实测 +12%）
- 容错：每 1MB 块 128 个坏 shard 可修 + 每组 64 个整块死亡可重建；超限精确判死
- 测试：**36 项全绿**（尺寸边界/损坏矩阵/文件级救援极限/截断篡改/并发 race），全量 ~72s
- API：`NewWriter(dst, key32, WithWorkers/WithInflight)` / `Open(src, key)` → `ReadAt`/`ReadChunkAt`（透明修复）/ `Verify`（只读）/ `Scrub`（就地修复+报告）

## 6. 编码性能剖析与优化历程：35.8 → 59 MB/s（+65%）

### 6.1 起点：串行 v0 = 35.8 MB/s（memFile 基准，每 1MB 块 27ms）

| 阶段 | ms/块 | 占比 | 性质 |
|---|---:|---:|---|
| 块内 RS leopard | 8.8 | 27.0% | **纯单线程**（上游 leopard 零 goroutine，WithMaxGoroutines 无效） |
| 文件级 RS classic | 8.7 | 26.6% | 已多核 |
| 槽位落盘（384×4KB 逐槽） | 7.5 | 22.8% | 系统调用开销（可合并） |
| parity 写 | 4.0 | 12.1% | |
| tag SHA×384 | 1.4 | 4.2% | |
| GCM | 1.0 | 3.1% | 硬件指令 |
| 读回/组装 | 1.4 | 4.3% | |

流式并行分析：除"文件级 parity 必须等满 128 块"（组屏障）外全部可流水。

### 6.2 三步优化

| 步骤 | 改动 | 吞吐 | 增量 |
|---|---|---:|---|
| v0 串行 | — | 35.8 | — |
| C+：槽位合并 + w4-f16 worker pool + 池化 | 384 次小写→1 次大写；4 worker 三段流水；sync.Pool 四级缓冲 | 53.1 | +48% |
| v2：parity-first 无屏障布局 | 组内 parity 前置；blob/par 零拷贝移交后台累加器（窗口全落在连续区段，免读回免拷贝） | **~59**（56.5-61.7 波动带） | +11% |

### 6.3 参数与调度的实测结论

- **全核 GOMAXPROCS=8 优于钉大核**（59 vs 33-40）：小核参与的并行度收益 > 单核速度差；
- 最优参数 **w4-f16**（4 worker + 16 in-flight，内存 ~52MB）：w6/w8 过订撞内存带宽墙反而下降；
- 两个反直觉证伪：文件级 codec 限核让路 workers → 反降到 51.4；in-flight 深挖收益边际递减。

### 6.4 最终地板的定性

**LPDDR 内存带宽**：4 个并发编码器 + parity 计算同时流式扫内存即饱和（与 gfbench"8 路并行仅 1.84x"吻合）。板上继续提升只剩 NEON SIMD 内核（改每字节指令数）或格式减冗余（改 GF 总量），均为大工程，性价比已被证伪。

## 7. 硬件加速可行性裁定（全部实测）

| 路线 | 裁定 | 依据 |
|---|---|---|
| NPU 加速 RS | ❌ 语义不兼容 | NPU=实数 MAC 阵列跑 NN 图；RS=GF(256) 模乘+XOR 累加，表达不成神经网络；且设备节点已消失 |
| GPU OpenCL | ❌ 平台不存在 | clinfo 0 平台 |
| Crypto Engine | ❌ 无 RS 算法 | 且内核未启用 |
| 自研 cgo NEON 内核 | ❌ 输给现库 | 同配置 70.8 vs 164.5 MB/s（klauspost vtbl 已近内存带宽） |
| 换库/换指令/开并行 | ❌ 无低垂果实 | 逐项试完：leopard 单线程是库特性、X 已 10.8GB/s |
| amd64 迁移 | ✅ 15-30× 推算 | AVX2 leopard 3-8GB/s（vs 0.12）；C+ 预计 1-2GB/s；ashou.site（2vCPU Xeon AVX2）可做异地巡检节点，不宜编码主力 |

## 8. 被证伪/否决的路线清单（省后人踩坑）

1. **memFile O(n²) 假信号**：测试替身 len 贴齐写入终点→顺序写全量重分配→0.4MB/s 假瓶颈（改 append 语义修复）；性能基准务必先排除测试基建
2. **openssl -engine afalg 数据**：异步引擎测量失真，10.5GB/s 假值
3. **qemu-x86_64 跑 amd64 基准**：解释执行不代表 AVX2 性能（慢 50-100×）
4. **副本防成片坏块质疑**：副本价值在"错得和本体不一样"（位置局域损坏 × 独立介质 = 概率乘积）；且带 ECC 格式的副本可自愈，五环节保副本架构坍缩为"月度 rsync + 季度 scrub"
5. **202MB RAM 缓存整组 blob 消读回**：只省 0.8ms/块，空间收益比荒谬
6. **k+m 过多是隐形杀手**：k=256 vs k=16 差 20 倍，远超一切实现层优化

## 8.5 重构期新增踩坑（2026-09）

1. **缓冲所有权移交**：v2 零拷贝移交 blob/par 给 parity 后台 goroutine 后，编码 worker 不得提前回收到 sync.Pool（use-after-free：parity 读到被后续块覆写的缓冲，产生系统性 parity 错误，仅文件级重建路径暴露）。规则：**移交即弃权，接收方负责回收**。
2. **ExtractPayloads 步长**：从 (payload+tag) 交错缓冲抽列必须用 `SlotSize(4112)` 步长而非 `ShardSize(4096)`——一个字符之差导致所有文件级 RS 重建错位（shard0 恰巧因 RS 首行系数全 1 而"看起来对"，掩蔽了 bug，debug 极难）。纯函数必须配表驱动单测锁死语义。

## 9. 交付物清单

| 路径 | 内容 |
|---|---|
| `secvault/` | 加密库 v2（format/core/writer/reader/scrub/crypto/errors + FORMAT.md） |
| `secvault/*_test.go` | 36 项测试 + 基准 + profile 分阶段剖析（-short 跳过大文件） |
| `gfbench/` | 独立 GF 基准套件（C NEON vtbl 内核 + klauspost 对照 + 频率监控） |
| `bench_afalg.py` `bench-openssl-big.txt` | 内核 AF_ALG 基准脚本与 OpenSSL 原始数据 |
| 本文档 | 实验总结 |

复现命令：
```bash
export PATH=/opt/go/bin:$PATH GOCACHE=$PWD/.gocache GOMODCACHE=$PWD/.gomodcache GOPATH=$PWD/.gopath
go test ./secvault/                    # 全量测试
go test -run '^$' -bench . -benchtime 4x ./secvault/   # 基准
taskset -c 6,7 gfbench/gfbench         # GF 基准（大核）
```

## 10. 后续路线图（按需）

1. **近期**：CLI 工具（pack/verify/scrub/extract）→ vidsite 接入（入库打包 + Range 播放）
2. **运维**：月度 scrub 实践（巡检即修复）+ 每月 rsync 冷备到异品牌盘（无副本设计的残余风险对冲）+ SSH 密码轮换（会话记录曾带出明文）
3. **观察一个巡检周期后**：按真实损坏模式（零星 bit vs 成片坏块）决定 v3 走混合 XOR 还是复制型
4. **远期可选**：amd64 编码节点（预期 1-2GB/s）+ 板子存储/巡检的分工架构
