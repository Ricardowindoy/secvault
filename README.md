# secvault

方案 C 视频加密容器库：**AES-256-GCM 认证加密 + 双层 Reed-Solomon 纠错**。
防 bit 反转（篡改检测 + 损坏恢复），无副本，月度巡检（scrub）自愈。

## 特性

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

// 写入
f, _ := os.Create("video.svdat")
w, _ := secvault.NewWriter(f, key, secvault.WithWorkers(4))
io.Copy(w, src) // 流式，Write 返回 ≠ 已落盘
w.Close()       // 必须：排空流水线 + 写 trailer

// 读取（io.ReaderAt 语义，透明修复）
r, _ := secvault.Open(f, key)
plain, _ := r.ReadChunkAt(0, nil)
n, _ := r.ReadAt(buf, offset)

// 巡检（月度，就地修复）
rep, _ := secvault.Scrub(f, key, secvault.Options{RebuildParity: true})
```

## API

| 符号 | 说明 |
|---|---|
| `NewWriter(dst io.ReadWriteSeeker, key, opts...)` / `Write` / `Close` | 流式写（异步流水线，错误延后到 Write/Close） |
| `Open(src io.ReaderAt, key)` → `Reader.ReadAt` / `ReadChunkAt` / `PlainSize` / `ChunkCount` | 读（透明修复，并发安全） |
| `Verify(src, key, opts)` | 只读深度校验报告 |
| `Scrub(rw, key, opts)` | 就地修复（坏槽/整块重建/可选 parity 重算） |
| `WithWorkers(n)` / `WithInflight(n)` | 流水线旋钮（默认 4/16，每 in-flight 块 ~2.6MB） |

## 文档

- `FORMAT.md` — 格式规范 v2（布局/块头/manifest/trailer）
- `EXPERIMENTS.md` — 全部实验结论与踩坑（性能剖析、GF 基准、被证伪路线）
- `REFACTOR.md` — 模块化重构记录

## 测试

```bash
go test ./unit/          # 36 项单测（含损坏矩阵/文件级救援极限/截断篡改）
go test -race ./unit/    # 竞态检测
go test ./bench/         # 基准与分阶段剖析
```

## 布局

```
secvault/
├── *.go                 # 生产门面（writer/reader/scrub/errors）
├── internal/            # layout/format/crypto/codec/engine + testutil
├── unit/                # 单元测试
└── bench/               # 基准/剖析/GF 工具
```
