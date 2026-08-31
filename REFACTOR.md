// Package secvault — 模块化重构方案（供审查）
//
// 现状问题诊断：
// 1. writer.go（486 行）混杂五种职责：API 门面、流水线编排、块编码、
//    文件级 RS 计算、I/O 原语 —— 修改任一关注点都要在 486 行里跳
// 2. core.go（345 行）同时承担：容器打开/清单校验、块读取+两级修复、
//    文件级重建、GCM 终审 —— Reader 与 Scrub 的共享底座变成了大杂烩
// 3. 布局数学（blobOffset 等）与序列化（trailer 编解码）混在 format.go
// 4. crypto.go 里放着一处无用的 ones() 函数；cipherAEAD 别名定义位置随意
// 5. writeGroupParity/codec 缓存在 writer 与 core 各有一套（语义不同但易混淆）
//
// 重构目标：单一职责、依赖单向（api → pipeline/codec/repair → layout/format → crypto），
// 包内分层子包，公共 API 不变（零破坏），测试与基准原样通过。

# 重构方案：secvault 分模块

## 一、目标包结构（internal 分层，公共 API 不变）

```
secvault/
  secvault.go          # 包文档 + 公共 API 汇出口（NewWriter/Open/Verify/Scrub/错误/选项）
  writer.go            # Writer 门面：Write/Close 语义、选项、生命周期（~120 行）
  reader.go            # Reader 门面：Open/ReadAt/ReadChunkAt + 缓存（~100 行）
  scrub.go             # Verify/Scrub 门面 + Report（~90 行）
  internal/
    layout/            # 纯函数布局数学（零依赖）
      layout.go        #   blobOffset/parityBlobOffset/groupCount/totalBlobCount/...
    format/            # 磁盘格式结构编解码（依赖 layout）
      chunk.go         #   chunkHeader 32B 编解码
      manifest.go      #   manifest JSON + trailer 40B 帧 + CRC32C
    crypto/            # 密码学原语（依赖无）
      keys.go          #   HKDF 派生、GCM 构造
      tag.go           #   shardTag/verifyTag
    codec/             # RS 编解码器（依赖无）
      codec.go         #   编码器缓存（intra 256+128 / file k+64）、warmup
      window.go        #   窗口切片视图（blob/par → shard 列，零拷贝）
    engine/            # 编排引擎（依赖 layout/format/crypto/codec）
      pipeline.go      #   写入流水线：worker 池、有序落盘、parity 累加器（从 writer.go 抽出）
      chunkio.go       #   块 I/O：gatherBlob（含 tag 验证）
      repair.go        #   两级修复：repairIntra / rebuildMissing（文件级）
      verify.go        #   decodeChunk（头解析+GCM 终审）、loadChunk 编排
      open.go          #   容器打开：size 解析、trailer 定位、manifest 解密、core 装配
  FORMAT.md / EXPERIMENTS.md
  *_test.go（测试文件名同步重命名，引用 internal 路径）
```

## 二、职责边界（每个模块一句话）

| 模块 | 唯一职责 | 明确不做 |
|---|---|---|
| layout | 整数偏移数学（纯函数） | 任何 I/O、序列化 |
| format | 块头/manifest/trailer 的字节级编解码 | 解密、校验语义 |
| crypto | 密钥派生、AEAD、tag 计算 | 任何布局知识 |
| codec | RS 编码器的构造与缓存、shard 窗口视图 | 何时调用（编排不在此） |
| engine.pipeline | 写入三段流水的并发编排 | 加密细节（调 codec/crypto） |
| engine（chunkio/repair/verify） | 读取侧：收集→块内修复→文件级重建→GCM 终审 | 写路径 |
| engine.open | 把字节流装配成可用 core（含全部健康校验） | 修复逻辑 |
| writer/reader/scrub（顶层） | API 门面：参数、语义、生命周期 | 一切实现细节 |

## 三、依赖方向（单向，禁止反向）

```
writer/reader/scrub (API)
        │
        ▼
engine (pipeline / chunkio+repair+verify / open)
        │
        ▼
codec ──► crypto ──► (stdlib)
  │                    ▲
  └──► format ──► layout
```

规则：layout 不 import 任何兄弟包；format 只 import layout；engine 可用全部；
顶层只 import engine 与（暴露类型所需的）format 错误。**internal 保证外部不可见。**

## 四、迁移映射（旧 → 新）

| 旧位置 | 新位置 |
|---|---|
| format.go: 布局函数 111-149 行 | internal/layout/layout.go |
| format.go: chunkHeader | internal/format/chunk.go |
| format.go: manifest+trailer+validate | internal/format/manifest.go |
| crypto.go: deriveKey/newGCM | internal/crypto/keys.go |
| crypto.go: shardTag/verifyTag | internal/crypto/tag.go（删 ones()） |
| writer.go: WriterOption/opts | writer.go（门面保留） |
| writer.go: chunkJob/parityMsg/三 loop/writeParityGroup/warmup/fileCodec | engine/pipeline.go + codec/ |
| writer.go: encodeJob | engine/pipeline.go |
| core.go: openCore/resolveSize | engine/open.go |
| core.go: gatherBlob | engine/chunkio.go |
| core.go: repairIntra/rebuildMissing/rebuildBlobFileLevel | engine/repair.go |
| core.go: decodeChunk/loadChunk/dataChunks | engine/verify.go |
| core.go: extractPayloads | codec/window.go |
| reader.go / scrub.go 骨架 | 保留顶层，内部改调 engine |
| errors.go / secvault.go | 顶层（errors 不动） |

## 五、关键设计决策

1. **公共 API 零破坏**：NewWriter/Open/ReadAt/Verify/Scrub/WithWorkers 签名不变；
   内部类型（chunkJob/core/parityMsg）全部下沉 internal，不再暴露。
2. **codec 单一实例化点**：intra（256+128）与 file（k,64）编码器只在一个缓存结构中构造
   （含 warmup），writer 与读取侧共用同一缓存实现（各自持有实例），消灭两套 fileCodec。
3. **pipeline 与门面解耦**：Writer 结构只剩选项+句柄+错误；流水线状态全部收进
   engine.pipeline 的独立结构体，便于将来单独测试流水线。
4. **测试策略**：现有 36 项测试改为通过公共 API 黑盒跑（本来几乎全是）；
   internal 单测可后补（layout/format 纯函数适合表驱动）。
5. **不做**：接口抽象化（当前唯一实现，YAGNI）、包外错误细化、行为变更。

## 六、验收标准（与重构前逐项对齐）

1. `gofmt / go vet` 干净；
2. `go test ./secvault/...` 36 项全绿（含 130 块大测试）；
3. `go test -race -short` 通过；
4. `BenchmarkEncode` 维持 56-62 MB/s 区间（性能无回退，波动 ±5% 内）；
5. 公共 API godoc 无变化（`go doc` 输出 diff 为空）；
6. 各源文件 ≤ 350 行，单一文件不再含两种顶层职责。

## 七、实施结果（已完成）

- 全部迁移完成，公共 API 零破坏（NewWriter/Open/ReadAt/Verify/Scrub/WithWorkers/WithInflight 签名不变）。
- 结构：顶层门面 6 文件（secvault/writer/reader/scrub/errors）+ internal 5 子包（layout/format/crypto/codec/engine）。
- 测试组织：单元测试（36 项）随顶层包；基准/剖析/GF 工具移入 `bench/`（bench_test.go、profile_test.go、gfbench/）。
- 回归：全量 60.8s ✅、race 306s ✅、编码基准 54-62 MB/s（无回退）。
- 过程修复的 bug：
  1. **pipeline 提前回收 blob/par**（v2 零拷贝移交引入 use-after-free → parity 读到被覆写缓冲）；修复：所有权移交 parityLoop，flush 后回收。
  2. **codec.ExtractPayloads 步长错用 ShardSize(4096) 应为 SlotSize(4112)**（重构时引入，漏跳 tag 导致文件级重建系统性错误）；修复并加注释防回退。
