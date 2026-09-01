# secvault

视频加密容器库：**AES-256-GCM 认证加密 + Reed-Solomon 纠错**，按内容类别分三种 scheme（v3）。
防 bit 反转（篡改检测 + 损坏恢复），无副本，月度巡检（scrub）自愈。

## 特性

### v3 三类别 scheme（详见 `FORMAT-v3.md`）
- **gcm-only**（`WithRePull()`）：可重拉小文件（缩略图/元数据/字幕），~1× 空间，单 GCM 单元，损坏→重拉
- **rs-strong**（`WithStrongRS()`）：不可重拉小文件 <1MB，固定 RS(32,64) 变长 shardSize，96 槽，~3.15×，66.7% 散落容错
- **rs-dual**（`WithFileParity(m)` / 默认）：视频 ≥1MB，v2 双层 RS + v3.0 自适应文件级 parity（末组 `min(M2,kLast)`）

### v2 基线（rs-dual，默认）
- 分块 AES-256-GCM（每块 1MB 明文，nonce 全局唯一，块头为 AAD）
- 块内 RS(256,128)（4KB shard + 16B 截断 SHA-256 tag 定位坏块）
- 文件级 RS(128,64)（组内 parity 在前 → **写入无屏障**，数据写与 parity 计算全并行）
- 读取路径透明修复：块内 ≤128 坏 shard 内存重建，超出整块文件级重建
- `Verify` 只读深度校验 / `Scrub` 就地修复 + 报告
- 纯 Go 跨架构（arm64 写的容器可在 amd64 上 scrub/重建）
- 性能（A733 实测）：编码 ~57 MB/s，读取 ~250-280 MB/s

## 使用

```go
key := make([]byte, 32) // 主密钥，32 字节

// v3 scheme 选择（opt-in；缺省写 v2 rs-dual）
w, _ := secvault.NewWriter(f, key, secvault.WithRePull())       // gcm-only（可重拉小文件）
w, _ := secvault.NewWriter(f, key, secvault.WithStrongRS())     // rs-strong（不可重拉 <1MB）
w, _ := secvault.NewWriter(f, key, secvault.WithFileParity(64)) // rs-dual v3（自适应 parity）
w, _ := secvault.NewWriter(f, key)                              // 缺省 v2

io.Copy(w, src) // 流式（rs-dual 异步流水线；gcm-only/rs-strong 同步缓冲，Close 一次编码）
w.Close()       // 必须：排空后端 + 写 trailer

// 读取（io.ReaderAt 语义，透明修复；scheme 自动分派）
r, _ := secvault.Open(f, key)
plain, _ := r.ReadChunkAt(0, nil)
n, _ := r.ReadAt(buf, offset)

// 巡检（月度，就地修复）
rep, _ := secvault.Scrub(f, key, secvault.Options{RebuildParity: true})
```

## API

| 符号 | 说明 |
|---|---|
| `NewWriter(dst, key, opts...)` / `Write` / `Close` | 流式写（rs-dual 异步流水线；gcm-only/rs-strong 同步缓冲，Close 一次编码） |
| `Open(src, key)` → `Reader.ReadAt` / `ReadChunkAt` / `PlainSize` / `ChunkCount` | 读（透明修复，scheme 自动分派，并发安全） |
| `Verify(src, key, opts)` | 只读深度校验报告 |
| `Scrub(rw, key, opts)` | 就地修复（rs-dual 块/组级；rs-strong 逐槽；gcm-only 仅报告） |
| `WithRePull()` | gcm-only scheme（可重拉小文件，~1×） |
| `WithStrongRS()` | rs-strong scheme（不可重拉 <1MB，RS(32,64)，66.7% 容错） |
| `WithFileParity(m)` | rs-dual v3，文件级 parity 上限 m（1..64，自适应末组） |
| `WithWorkers(n)` / `WithInflight(n)` | rs-dual 流水线旋钮（默认 4/16，每 in-flight 块 ~2.6MB） |

## 文档

- `FORMAT.md` — 格式规范 v2（布局/块头/manifest/trailer）
- `FORMAT-v3.md` — v3 三类别方案设计定稿（gcm-only / rs-strong / rs-dual）
- `DESIGN-v3-phase2.md` — v3 phase 2 实现设计（函数签名级 spec）
- `EXPERIMENTS.md` — 全部实验结论与踩坑（性能剖析、GF 基准、被证伪路线）
- `REFACTOR.md` — 模块化重构记录

## 测试

```bash
go test ./unit/          # v2/v3 单测（损坏矩阵/文件级救援极限/66.7%容错边界/空文件/scheme 分派）
go test -race ./unit/    # 竞态检测
go test ./bench/         # 基准与分阶段剖析
```

## 布局

```
secvault/
├── *.go                 # 生产门面（writer/reader/scrub/errors）
├── internal/            # layout/format/crypto/codec/engine + testutil
├── unit/                # 单元测试（v2/v3/gcm-only/rs-strong）
└── bench/               # 基准/剖析/GF 工具
```
