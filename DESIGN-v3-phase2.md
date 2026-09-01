# secvault v3 第二阶段实现设计（gcm-only + rs-strong）

> 本文档是子代理施工的唯一 spec（子代理看不到设计对话）。函数签名、布局字节、
> 集成点、测试要求均已细化到可直接编码的程度。先通读全文再动手。
>
> **前置阅读**：`FORMAT-v3.md`（§4 gcm-only、§5 rs-strong、§7 manifest、§10 阶段2）、
> 现有 `internal/layout/layout.go`、`internal/codec/codec.go`、`internal/format/format.go`、
> `internal/engine/{pipeline,container}.go`、`writer.go`、`reader.go`、`scrub.go`。
>
> **不变量**：AES-256-GCM 认证加密（信任锚=tag）；RS 最外层、GCM 最内层；HKDF 派生；
> 截断 SHA-256(16B) shard tag 仅用于意外损坏定位。这些在 crypto.go 已有，复用。

## 0. 范围与策略

- **本阶段实现**：gcm-only 与 rs-strong 两个 scheme 全栈（layout→codec→format→errors→engine→顶层 API→scrub→测试）。
- **策略：opt-in 优先**。默认写出版本仍为 v2（无 option）或 v3 rs-dual（`WithFileParity`）；
  gcm-only/rs-strong 由**显式 option** 触发。`FORMAT-v3.md §3.1` 的"默认按尺寸自动分档"
  （plainSize<1MB→rs-strong）留待第三阶段（需混合状态机：缓冲到 1MB 阈值再决策，
  复杂度高），**本阶段不做**，与 v3.0 的 opt-in 渐进策略一致（`FORMAT-v3.md:8`）。
- **模型**：子代理 `local/ox-alpha-free`，`reasoning_effort=high`。
- **分批**（串行，批次2 依赖批次1 落盘的底层改造）：
  - **批次1（子代理A）**：共享底层 scheme 感知改造（layout 常量+尺寸函数、codec.Strong、
    format manifest Scheme+Validate 分派、errors 哨兵）+ gcm-only 全栈 + gcm-only 测试。
  - **批次2（子代理B）**：rs-strong 全栈 + rs-strong 测试（读批次1 已落盘的底层）。
- **每批结束的验收门禁**：`go build ./...` 通过 + 该批新增测试全绿 + 原有 v2/v3.0 测试不回归。
  全部完成后 `go test ./...` 全绿。

---

## 1. 架构决策（必读）

### 1.1 Writer 策略分派（核心难点）

现有 `Writer`（`writer.go:62`）直接持有 `*engine.Pipeline`——rs-dual 的流式无屏障流水线
（主 goroutine 切块→workers 并行 GCM+RS→落盘 goroutine 按序写→parityLoop 后台算组级 parity）。

gcm-only / rs-strong 是**"单 blob 缓冲后一次性编码"**模式：
- gcm-only：整个文件一个 GCM 单元，必须缓冲全部明文才能 `aead.Seal`。
- rs-strong：`shardSize = ceil((HeaderSize+plainSize+TagSize)/K)`，必须知道 plainSize 才能算
  shardSize 才能布局，必须缓冲全部明文。

两者与流式 Pipeline 不兼容。**决策**：顶层 Writer 按 scheme 持有不同写入后端，不硬塞 Pipeline。

```go
// writer.go —— Writer 改为 sum-type 分派（不引入 interface，保持简单）
type Writer struct {
    dst      io.ReadWriteSeeker
    manAEAD  crypto.AEAD
    fileID   []byte
    version  int
    scheme   string           // "rs-dual" | "gcm" | "rs-strong"
    m2cap    int              // 仅 rs-dual 用
    pipeline *engine.Pipeline // scheme=="rs-dual" 时非 nil
    sink     engine.SmallFileSink // scheme!="rs-dual" 时非 nil（gcm/strong 各一实现）
    closed   bool
}
```

`engine` 包暴露 `SmallFileSink` 接口 + gcm/strong 两个实现；`Write`/`Close` 按 `scheme` 分派。
rs-dual 路径（Pipeline）**保持不变**，只是被包进分派里。

### 1.2 Container（读取侧）scheme 分派

现有 `Container.LoadChunk`（`container.go:291`）是 rs-dual 块级：gather→块内 RS→文件级 RS→GCM。
gcm-only/rs-strong 是文件级单 blob，无"块"概念。

**决策**：Container 按 `man.Scheme` 分派：
- rs-dual：`LoadChunk`（现有，**不动**）
- gcm-only / rs-strong：新增 `LoadAll() ([]byte, error)`，一次性返回全部明文。

顶层 `Reader` 按 scheme 分派：
- rs-dual：`ReadChunkAt`/`ReadAt`（现有块级，**不动**）
- gcm-only / rs-strong：首次访问时 `LoadAll()` 缓冲全部明文到 `Reader`，之后 `ReadChunkAt(0)`
  返回全部（其他 index 越界）、`ReadAt` 切片返回。`Reader` 已有单 chunk 缓存字段，扩展为
  "全量缓冲"语义即可。

### 1.3 manifest 字段语义按 scheme 分化

`FORMAT-v3.md §7` 设计的 manifest 结构。字段复用 v2 的 JSON tag，按 scheme 取舍：

| 字段 | rs-dual | gcm-only | rs-strong |
|---|---|---|---|
| `v` | 3 | 3 | 3 |
| `sc`(Scheme) | "rs-dual"(或空,兼容v2) | "gcm" | "rs-strong" |
| `k`/`m`(块内) | 256/128 | 省略(0) | 32/64(冗余记录) |
| `k2`/`m2`(文件级) | 128/m2cap | 省略(0) | 省略(0) |
| `ss`(ShardSize) | 4096 | 省略(0) | 变长 shardSize |
| `cp`(ChunkPlain) | 1048528 | 省略(0) | 省略(0) |
| `cc`(ChunkCount) | 块数 | 0(无分块) | 0 |
| `ps`(PlainSize) | 总明文 | 总明文 | 总明文 |
| `ks`(KStrong) | 省略 | 省略 | 32 |
| `ms`(MStrong) | 省略 | 省略 | 64 |

> 注意：rs-strong 的 `k=32`/`m=64` 复用了 v2 的 `k`/`m` 字段语义（块内 RS 维度），
> 但 rs-strong 没有"块"概念——这里 `k`/`m` 实际是 rs-strong 的 RS(32,64) 维度，
> 是同一对值的不同语义。Validate 按 scheme 分派解释即可，不冲突。

### 1.4 关键复用点

- **rs-strong 的 RS(32,64) 可复用 `codec.File(k,m)`**：现有守卫 `k∈[1,128]`、`m∈[1,64]`，
  `File(32,64)` 合法。reedsolomon 库的 Encoder 对 shardSize 不敏感（每个 shard 是任意长度
  `[]byte`，只要等长），变长 shardSize 无需新编码器。但 rs-strong 是 opt-in 单配置，
  本阶段新增 `codec.Cache.Strong()` 返回 warmup 过的 RS(32,64)（避免首次并发竞态，
  与 `Intra()` 模式一致）。
- **gcm-only 只需新增 HKDF info**：`"secvault/gcm/v1"`（区别于 chunk 的
  `"secvault/chunk/v1"`、manifest 的 `"secvault/manifest/v1"`）。
- **chunkHeader(32B) 复用**：rs-strong 复用 v2 的 32B 块头（`magic SVC1`+块序号+plainLen+nonce），
  GCM AAD = 块头；gcm-only 用自己的 16B 头（`magic SVGO`+nonce），不复用 chunkHeader。

---

## 2. 各层函数签名（按批次组织）

### 批次1 共享底层 + gcm-only

#### 2.1 internal/layout（新增常量 + 尺寸函数）

```go
// 新增常量（追加到现有 const 块）
const (
    // gcm-only 布局：[4B magic "SVGO"][12B nonce][GCM密文+tag (plainSize+16)B]
    magicGCMOnly   = "SVGO"
    GCMHeaderSize  = 4 + NonceSize  // = 16 (magic + nonce)

    // rs-strong 布局参数（FORMAT-v3.md §5.1，固定）
    KStrong        = 32             // 数据 shard
    MStrong        = 64             // 校验 shard (M=2K)
    StrongSlots    = KStrong + MStrong  // = 96 槽
)

// ---- gcm-only 尺寸（纯函数，零依赖）----

// GCMOnlyPayloadSize gcm-only 正文载荷 = 头(16) + plainSize + GCM tag(16)
func GCMOnlyPayloadSize(plainSize int64) int64 {
    return int64(GCMHeaderSize) + plainSize + int64(TagSize)
}

// GCMOnlySize gcm-only 容器总大小 = 载荷 + trailer
func GCMOnlySize(plainSize, trailerLen int64) int64 {
    return GCMOnlyPayloadSize(plainSize) + trailerLen
}

// ---- rs-strong 尺寸（纯函数，零依赖）----

// StrongShardSize rs-strong 单 shard 载荷 = ceil((HeaderSize + plainSize + TagSize) / KStrong)
//   RS 数据区 = chunkHeader(32) || GCM密文+tag(plainSize+16) || 零填充，总长向上取整到 KStrong 倍数
func StrongShardSize(plainSize int64) int64 {
    dataLen := int64(HeaderSize) + plainSize + int64(TagSize) // 32 + plainSize + 16
    return (dataLen + KStrong - 1) / KStrong
}

// StrongSlotSize rs-strong 单槽落盘 = shardSize + TagSize(16)
func StrongSlotSize(plainSize int64) int64 {
    return StrongShardSize(plainSize) + int64(TagSize)
}

// StrongPayloadSize rs-strong 正文落盘 = 96 × (shardSize + TagSize)
func StrongPayloadSize(plainSize int64) int64 {
    return int64(StrongSlots) * StrongSlotSize(plainSize)
}

// StrongSize rs-strong 容器总大小 = 正文 + trailer
func StrongSize(plainSize, trailerLen int64) int64 {
    return StrongPayloadSize(plainSize) + trailerLen
}
```

#### 2.2 internal/codec（新增 Strong 编码器）

```go
// Cache 新增字段：strong reedsolomon.Encoder（在 NewCache 时一并构造 + warmup）
type Cache struct {
    mu    sync.Mutex
    intra reedsolomon.Encoder
    strong reedsolomon.Encoder  // 新增：RS(32,64) 固定，warmup 过
    files map[[2]int]reedsolomon.Encoder
}

// NewCache 扩展：额外构造 + warmup strong 编码器。
// warmup 必须在首次 Encode 前完成（避免 reedsolomon 库延迟初始化的并发竞态，同 Intra）。
func NewCache() (*Cache, error) {
    intra, err := reedsolomon.New(layout.DataShards, layout.ParityShards)
    if err != nil { return nil, ... }
    if err := warmup(intra); err != nil { return nil, ... }
    strong, err := reedsolomon.New(layout.KStrong, layout.MStrong)  // RS(32,64)
    if err != nil { return nil, fmt.Errorf("secvault: strong codec: %w", err) }
    if err := warmup(strong); err != nil { return nil, fmt.Errorf("secvault: strong warmup: %w", err) }
    return &Cache{intra: intra, strong: strong, files: map[[2]int]reedsolomon.Encoder{}}, nil
}

// Strong 返回 rs-strong 固定 RS(32,64) 编码器（warmup 过）。
func (c *Cache) Strong() reedsolomon.Encoder { return c.strong }
```

> 注意：`warmup` 现有用 `layout.ShardsPerBlob` 个 shard 做编码；strong warmup 要用
> `layout.StrongSlots`(96) 个 shard。`warmup` 签名已是 `func warmup(enc reedsolomon.Encoder) error`
> 内部固定 ShardsPerBlob——需改为接收 shardCount 参数，或新增 `warmupN(enc, n)`。
> 推荐：改 `warmup` 内部按 `enc.(...)` 无法拿 shardCount，最简单是新增
> `func warmupN(enc reedsolomon.Encoder, n int) error`，`warmup` 调 `warmupN(enc, layout.ShardsPerBlob)`。

#### 2.3 internal/format（manifest Scheme + Validate 分派）

```go
// Scheme 类型与常量
type Scheme string
const (
    SchemeRSDual   Scheme = "rs-dual"
    SchemeGCMOnly  Scheme = "gcm"
    SchemeRSStrong Scheme = "rs-strong"
)

// Manifest 新增字段（追加到现有 struct）
type Manifest struct {
    // ... v2 字段不变（v/k/m/k2/m2/ss/cp/cc/ps）...
    Scheme  string `json:"sc,omitempty"` // v3 scheme；rs-dual 可省略（v2 兼容，空=rs-dual）
    KStrong int    `json:"ks,omitempty"` // rs-strong=32，其他省略
    MStrong int    `json:"ms,omitempty"` // rs-strong=64，其他省略
}

// ResolveScheme 从 manifest 解析 scheme（空/缺失 → rs-dual，向后兼容 v2）
func (m *Manifest) ResolveScheme() Scheme {
    if m.Scheme == "" { return SchemeRSDual }  // v2/旧 v3 无字段 → rs-dual
    return Scheme(m.Scheme)
}

// ResolveSpec 现有逻辑保留（按 Version 分派 v2/v3 rs-dual）。
// gcm-only/rs-strong 的布局参数不经 Spec（它们是文件级单 blob，无组/块概念），
// 尺寸函数直接用 layout.GCMOnlySize/StrongSize。

// Validate 改为按 scheme 分派尺寸校验（FORMAT-v3.md §7）
func (m *Manifest) Validate(size, trailerLen int64) error {
    // 公共校验：version、plainSize 非负、chunkCount 非负 保留
    // ...
    switch m.ResolveScheme() {
    case SchemeGCMOnly:
        // rs-dual 专有字段必须为零（k/m/k2/m2/ss/cp/cc 都应省略或 0）
        // 尺寸：size == GCMOnlySize(plainSize, trailerLen)
        if expect := layout.GCMOnlySize(m.PlainSize, trailerLen); expect != size {
            return errors.ErrNoManifest
        }
    case SchemeRSStrong:
        // ks/ms 冗余校验：ks==KStrong(32), ms==MStrong(64)
        // ss 必须等于 StrongShardSize(plainSize)
        // 尺寸：size == StrongSize(plainSize, trailerLen)
        if m.KStrong != layout.KStrong || m.MStrong != layout.MStrong {
            return errors.ErrUnsupportedFormat
        }
        if m.ShardSize != int(layout.StrongShardSize(m.PlainSize)) {
            return errors.ErrUnsupportedFormat
        }
        if expect := layout.StrongSize(m.PlainSize, trailerLen); expect != size {
            return errors.ErrNoManifest
        }
    default: // rs-dual（含 v2 兼容）
        // 现有 rs-dual 校验逻辑（k/m/k2/m2/ss/cp 守卫 + TotalBlobCount 尺寸）
        // 注意 m2 版本感知逻辑保留
    }
    return nil
}
```

#### 2.4 internal/errors（新增哨兵）

```go
var (
    // ErrGCMOnlyCorrupted gcm-only 容器 GCM.Open 失败：检测到损坏/篡改，
    // 本类别定义如此（损坏→调用方重拉），无修复路径。
    ErrGCMOnlyCorrupted = errors.New("secvault: gcm-only container corrupted (re-pull required)")
)
```

#### 2.5 internal/engine —— gcm-only 读写

```go
// engine 包暴露 SmallFileSink 接口（gcm-only + rs-strong 共用缓冲语义，各一实现）
type SmallFileSink interface {
    // Write 缓冲明文（gcm-only/strong 都是单 blob，先全收下）
    Write(p []byte) (int, error)
    // Drain 编码 + 落盘 + 返回 (plainSize)。scheme 由实现固定，调用方已知。
    Drain() (plainSize int64, err error)
}

// ---- gcm-only 写入后端 ----
type gcmOnlySink struct {
    dst   io.ReadWriteSeeker
    aead  crypto.AEAD       // HKDF(master, fileID, "secvault/gcm/v1")
    buf   []byte            // 明文缓冲（增长式）
}

func newGCMOnlySink(dst io.ReadWriteSeeker, aead crypto.AEAD) *gcmOnlySink {
    return &gcmOnlySink{dst: dst, aead: aead}
}

func (g *gcmOnlySink) Write(p []byte) (int, error) { g.buf = append(g.buf, p...); return len(p), nil }

// Drain: nonce 随机 → Seal(buf, nonce, nil, header) → 写 [magic+nonce][密文+tag] 到偏移0
func (g *gcmOnlySink) Drain() (int64, error) {
    nonce, _ := crypto.RandomBytes(layout.NonceSize)
    header := make([]byte, layout.GCMHeaderSize) // [4B SVGO][12B nonce]
    copy(header, layout.MagicGCMOnly())  // 暴露 magic 常量访问器
    copy(header[4:], nonce)
    ct := g.aead.Seal(nil, nonce, g.buf, header)  // AAD = 16B 头
    out := append(header, ct...)  // 注意：header 已含 magic+nonce
    // 写到偏移 0（trailer 由顶层 Writer 在之后追加）
    if _, err := g.dst.Seek(0, io.SeekStart); err != nil { return 0, err }
    _, err := g.dst.Write(out)
    return int64(len(g.buf)), err
}

// ---- Container gcm-only 读取 ----
// Container 新增方法（按 man.Scheme 在 Open 后分派，或 Reader 首次访问时调）
func (c *Container) LoadGCMOnly() ([]byte, error) {
    payloadSize := layout.GCMOnlyPayloadSize(c.Man.PlainSize)
    buf := make([]byte, payloadSize)
    if _, err := c.src.ReadAt(buf, 0); err != nil && err != io.EOF {
        return nil, err
    }
    // header = buf[:16], ct = buf[16:16+plainSize+16]
    // 注意：gcm-only magic 在 header[:4]，可选校验
    header := buf[:layout.GCMHeaderSize]
    nonce := header[4:]
    ct := buf[layout.GCMHeaderSize : layout.GCMHeaderSize+c.Man.PlainSize+layout.TagSize]
    plain, err := c.aead.Open(nil, nonce, ct, header) // AAD=header
    if err != nil {
        return nil, ierrors.ErrGCMOnlyCorrupted  // 检测到损坏→交调用方重拉
    }
    return plain, nil
}

// Container 新增统一入口（按 scheme 分派）
func (c *Container) LoadAll() ([]byte, error) {
    switch c.Man.ResolveScheme() {
    case SchemeGCMOnly:
        return c.LoadGCMOnly()
    case SchemeRSStrong:
        return c.LoadStrong()  // 批次2 实现
    default:
        return nil, ierrors.New("secvault: LoadAll on rs-dual (use LoadChunk)")
    }
}
```

#### 2.6 顶层 writer.go / reader.go / scrub.go —— gcm-only option + 分派

```go
// writer.go 新增 option
// WithRePull 声明内容可从源站重拉（缩略图/元数据/字幕）→ gcm-only scheme（~1×空间，
// GCM.Open 失败即报损坏交调用方重拉，无 RS 修复）。与 WithFileParity 互斥。
func WithRePull() WriterOption {
    return func(o *writerOpts) { o.scheme = "gcm"; o.formatV3 = true }
}

// writerOpts 新增字段：scheme string（缺省 ""=rs-dual）
// NewWriter：scheme=="gcm" 时构造 gcmOnlySink（aead 用 "secvault/gcm/v1" info），
//   不构造 Pipeline；Close 时 sink.Drain() 后写 trailer（offset = GCMOnlyPayloadSize(plainSize)）。

// reader.go Reader 扩展：新增 allPlain []byte 字段（gcm-only/strong 缓冲）。
//   ReadChunkAt：scheme!=rs-dual 时首次 LoadAll 缓冲，index==0 返回全部，其他越界。
//   ReadAt：scheme!=rs-dual 时首次 LoadAll 缓冲，切片返回。

// scrub.go：gcm-only 无修复路径。Verify 检测到 GCM.Open 失败 → Report 标记损坏
//   （复用 ChunksLost 语义：整文件=1个"块"，损坏则 ChunksLost=[0]）。Scrub 对 gcm-only
//   不回写（无冗余可修），仅报告。
```

#### 2.7 gcm-only 测试（unit/gcm_only_test.go）

```go
// TestGCMOnlyRoundTrip 往返：WithRePull() 写 KB~近1MB 明文 → Open → 全量读 + ReadAt 切片 + ReadChunkAt(0)
// TestGCMOnlySize 文件尺寸 == GCMOnlySize(plainSize, trailerLen)
// TestGCMOnlyManifest trailer.Version=3, manifest.Scheme="gcm", PlainSize 一致
// TestGCMOnlyCorruption 翻转密文区 1 字节 → Open 报 ErrGCMOnlyCorrupted（errors.Is 可匹配）
// TestGCMOnlyTrailerOption 缺省（无 option）仍写 v2；WithRePull 写 v3 gcm（与 WithFileParity 互斥校验）
// 边界：plainSize=1B、plainSize=ChunkPlainSize(1MB 界)、plainSize=0（空文件，ps=0 容许？按 Validate 决策）
```

---

### 批次2 rs-strong 全栈

#### 2.8 internal/engine —— rs-strong 读写

```go
// ---- rs-strong 写入后端 ----
type strongSink struct {
    dst    io.ReadWriteSeeker
    aead   crypto.AEAD       // HKDF(master, fileID, "secvault/chunk/v1") —— 复用 chunk info
    codecs *codec.Cache
    buf    []byte            // 明文缓冲
}

func newStrongSink(dst io.ReadWriteSeeker, aead crypto.AEAD, codecs *codec.Cache) *strongSink {
    return &strongSink{dst: dst, aead: aead, codecs: codecs}
}

func (s *strongSink) Write(p []byte) (int, error) { s.buf = append(s.buf, p...); return len(p), nil }

// Drain（FORMAT-v3.md §5.2）：
//  1. nonce = 随机12B（注意：rs-strong 单 blob，nonce 不含块序号，纯随机）
//  2. hdr = ChunkHeader{Index:0, PlainLen:len(buf), Nonce}.Marshal()  // 复用 SVC1 32B 头
//  3. ct = aead.Seal(nil, nonce, buf, hdr)  // AAD = 块头
//  4. dataArea = hdr || ct || 零填充 到 KStrong*shardSize
//     shardSize = StrongShardSize(len(buf))
//     dataLen = 32 + len(buf) + 16; paddedDataLen = shardSize * KStrong
//  5. 切 32 个数据 shard（每个 shardSize B，连续切片，零拷贝视图）
//  6. codecs.Strong().Encode(shards[0:96])  // shards[32:96] 是输出校验 shard，预分配
//  7. 落盘 96 槽：每槽 = [shardSize B 载荷][16B ShardTag]，顺序写
//     off_i = i * (shardSize + TagSize)
//  8. 写到偏移 0；返回 plainSize
func (s *strongSink) Drain() (int64, error) { /* 见上 */ }

// ---- Container rs-strong 读取（LoadAll 分派）----
func (c *Container) LoadStrong() ([]byte, error) {
    shardSize := layout.StrongShardSize(c.Man.PlainSize)
    slotSize := shardSize + int64(layout.TagSize)
    // 1. 读 96 槽，逐槽 tag 验，收集坏槽
    payloads := make([][]byte, layout.StrongSlots)  // 每槽 shardSize
    bad := []int{}
    for i := 0; i < layout.StrongSlots; i++ {
        slot := make([]byte, slotSize)
        off := int64(i) * slotSize
        if _, err := c.src.ReadAt(slot, off); err != nil && err != io.EOF { return nil, err }
        payload := slot[:shardSize]
        tag := slot[shardSize:]
        payloads[i] = payload
        if !crypto.VerifyTag(payload, tag) { bad = append(bad, i) }
    }
    // 2. RS(32,64) 重建坏槽（容 ≤64 槽坏；>64 → 不可恢复）
    if len(bad) > 0 {
        if len(bad) > layout.MStrong {
            return nil, &ChunkError{Index: 0, Err: errors.ErrChunkUnrecoverable}
        }
        views := make([][]byte, layout.StrongSlots)
        copy(views, payloads)
        for _, i := range bad { views[i] = nil }
        if err := c.codecs.Strong().Reconstruct(views); err != nil {
            return nil, &ChunkError{Index: 0, Err: errors.ErrChunkUnrecoverable}
        }
        payloads = views
    }
    // 3. 拼数据区（前 32 个数据 shard）→ chunkHeader → GCM.Open（AAD=块头）
    dataArea := make([]byte, shardSize*layout.KStrong)
    for i := 0; i < layout.KStrong; i++ {
        copy(dataArea[i*shardSize:], payloads[i])
    }
    hdr, _ := format.ParseChunkHeader(dataArea[:layout.HeaderSize])
    need := hdr.PlainLen + layout.TagSize  // 16
    plain, err := c.aead.Open(nil, hdr.Nonce, dataArea[layout.HeaderSize:layout.HeaderSize+need], dataArea[:layout.HeaderSize])
    if err != nil {
        return nil, &ChunkError{Index: 0, Err: fmt.Errorf("%w (gcm auth)", errors.ErrChunkUnrecoverable)}
    }
    return plain, nil
}
```

#### 2.9 顶层 —— rs-strong option + scrub

```go
// writer.go
// WithStrongRS 声明内容为不可重拉的小文件（<1MB）→ rs-strong scheme
//（RS(32,64) 固定 96 槽，66.7% 散落容错，~3.15×空间）。与 WithFileParity/WithRePull 互斥。
func WithStrongRS() WriterOption {
    return func(o *writerOpts) { o.scheme = "rs-strong"; o.formatV3 = true }
}

// NewWriter：scheme=="rs-strong" 时构造 strongSink（aead 用 "secvault/chunk/v1"，codecs 用 NewCache）。
//   Close：sink.Drain() → manifest {Scheme:"rs-strong", K:32, M:64, ShardSize:StrongShardSize, KStrong:32, MStrong:64, ChunkCount:0, PlainSize} → trailer offset = StrongPayloadSize(plainSize)。

// scrub.go：rs-strong 逐槽 tag 修复（坏槽 RS 重建后回写载荷+tag）。
//   Verify：检测坏槽，可修复则标记 ChunksRepaired（整文件=1"块"）。
//   Scrub：重建坏槽 + 回写（io.WriterAt），可选 RebuildParity 对 rs-strong 无意义（单 blob）。
```

#### 2.10 rs-strong 测试（unit/rs_strong_test.go）

```go
// TestRSStrongRoundTrip 往返：WithStrongRS() 写 1B~1MB 明文 → Open → 全量读 + ReadAt + ReadChunkAt(0)
// TestRSStrongSize 文件尺寸 == StrongSize(plainSize, trailerLen)，覆盖 shardSize 向上取整边界
// TestRSStrongManifest Scheme="rs-strong", K=32, M=64, ShardSize=StrongShardSize(ps)
// TestRSStrongCorruptionMatrix 损坏矩阵：坏 1/8/16/32/63/64 槽 → 重建成功；坏 65 槽 → ErrChunkUnrecoverable
//   （逐步逼近极限 64，验证 66.7% 容错边界；复用 corruptV3Slot 模式但用 StrongSlotSize 偏移）
// TestRSStrongGCMAuth 翻转 RS 重建后的明文区（模拟 RS 修干净但 GCM 终审失败）→ ErrChunkUnrecoverable
// 边界：plainSize=1B（shardSize=ceil(49/32)=2）、plainSize=1MB-1、plainSize=1MB（分界点，仍 rs-strong）
```

---

## 3. 集成点与约束

### 3.1 option 互斥
`WithRePull` / `WithStrongRS` / `WithFileParity` 三者互斥（设置不同 scheme）。最后一个生效或报错？
**决策**：以最后一个 option 为准（简单，符合 Go option 惯例），但在 NewWriter 里若 scheme 冲突
（如同时出现 RePull + FileParity）记录 warning 不阻断。实际：`writerOpts.scheme` 字段后写覆盖前写。

### 3.2 trailer 偏移
- rs-dual：`spec.TotalBlobCount(cc) * BlobDiskSize`（现有）
- gcm-only：`GCMOnlyPayloadSize(plainSize)`（= 16 + plainSize + 16）
- rs-strong：`StrongPayloadSize(plainSize)`（= 96 × (shardSize + 16)）

顶层 Writer.Close 按 scheme 选偏移公式写 trailer。

### 3.3 reader 缓冲策略
gcm-only/rs-strong 都是"全量缓冲"：Reader 首次访问时 LoadAll()，明文驻留 `allPlain` 字段。
对小文件（<1MB）这是可接受的内存占用。`ReadChunkAt`/`ReadAt` 都从 `allPlain` 切片。
rs-dual 路径**不动**（保持块级缓存 + LoadChunk）。

### 3.4 Open 时的 scheme 分派
`engine.Open` 解析 manifest 后，`Container` 持有 `man.ResolveScheme()`。
现有 `LoadChunk` 路径只在 rs-dual 走；gcm-only/strong 走 `LoadAll`。
顶层 `Reader` 在构造时知道 scheme（从 `c.Man`），按此选 ReadChunkAt/ReadAt 实现。

### 3.5 scrub 分派
顶层 `Verify`/`Scrub`（`scrub.go`）按 scheme 分派：
- rs-dual：现有 `c.Scrub`（块级 + 文件级）
- gcm-only：`c.ScrubGCMOnly`（GCM.Open 失败→Report 标记，不回写）
- rs-strong：`c.ScrubStrong`（逐槽 tag 验→坏槽 RS 重建→回写）

### 3.6 v2 兼容
v2 文件无 `sc` 字段 → `ResolveScheme()` 返回 rs-dual → 走现有路径。**不破坏 v2 读取/scrub**。
gcm-only/rs-strong 的 trailer.Version=3；v2 trailer.Version=2。`ParseTrailer` 已支持 v2/v3。

---

## 4. 文件清单（每批产出）

### 批次1
- 修改：`internal/layout/layout.go`（+常量 +6 尺寸函数 + magic 访问器）
- 修改：`internal/codec/codec.go`（+strong 字段 +Strong() +warmupN）
- 修改：`internal/format/format.go`（+Scheme 类型常量 +Manifest 字段 +ResolveScheme +Validate 分派）
- 修改：`internal/errors/errors.go`（+ErrGCMOnlyCorrupted）
- 新增：`internal/engine/gcm_only.go`（gcmOnlySink + Container.LoadGCMOnly + LoadAll 分派）
- 修改：`writer.go`（+scheme 字段 +WithRePull +NewWriter/Write/Close 分派）
- 修改：`reader.go`（+allPlain 缓冲 +ReadChunkAt/ReadAt 分派）
- 修改：`scrub.go`（+gcm-only 分派）
- 修改：`internal/engine/scrub.go`（+SrubGCMOnly，如 engine 层有 scrub 编排）
- 新增：`unit/gcm_only_test.go`

### 批次2
- 新增：`internal/engine/strong.go`（strongSink + Container.LoadStrong）
- 修改：`writer.go`（+WithStrongRS +NewWriter 分派 strongSink）
- 修改：`scrub.go` / `internal/engine/scrub.go`（+rs-strong 逐槽修复）
- 新增：`unit/rs_strong_test.go`

---

## 5. 验收

每批结束：
1. `cd /home/radxa/project/secvault && go build ./...` 零错误
2. `go test ./...` 全绿（含原有 v2/v3.0 测试不回归 + 新增测试通过）
3. 新增 scheme 的往返/尺寸/manifest/损坏测试覆盖文档 §10 要求

全部完成：
- `FORMAT-v3.md` 更新实现状态行（gcm-only/rs-strong 标记已实现）
- `EXPERIMENTS.md` 可补 rs-strong 编码吞吐基准（可选）
