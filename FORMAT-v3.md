# secvault 格式规范 v3（设计定稿）

> **实现状态**：v3.0（rs-dual 自适应文件级 parity，`WithFileParity(m)` + data-first 布局）**已实现**（commit 05c642b）；
> gcm-only / rs-strong 两 scheme 尚未实现。现行 v2 见 `FORMAT.md`。
> v3 按**内容类别**分三种容器 scheme：`gcm-only` / `rs-strong` / `rs-dual`。
> 设计过程：从 v2 小文件浪费出发，历经"自适应 parity（v3.0）→ 变长末块（v3.1）→ mirror"多轮方案，
> 最终按用户确认的 p91 场景定稿为三类别方案（v3.1 变长末块与 mirror 均被否决，理由见 §3.4 / §8）。
> **实现说明**：v3.0 当前为 opt-in（默认仍写 v2），p91 接入阶段再翻默认。

## 1. 目标与不变量

### 1.1 不变的威胁模型（同 v2）
- 意外损坏（bit rot / 坏扇区 / 传输误码）→ RS 纠错恢复，GCM 终审。
- 恶意篡改（超 RS 纠错能力）→ GCM.Open 拒绝（2^-32 级漏检）。
- 介质整体报废 → 不设防（无副本），需外部冷备。

### 1.2 不变的安全锚点
- AES-256-GCM 认证加密，信任锚唯一：GCM tag。
- ECC 套密文外，GCM tag 纳入 ECC 保护域，重建后必过 GCM 终审。
- 分层澄清（用户曾质疑"GCM 在最上层放大 bit 翻转"）：**RS 是最外层，GCM 是最内层**。
  读路径 = 盘 → 逐槽 SHA-256 tag → RS 重建 → GCM.Open；GCM 只在 RS 修干净后运行，
  1 bit 翻转被外层 tag 雪崩捕获 + RS 逐比特精确重建，GCM 看到的是干净密文。GCM 本身是
  AEAD（CTR 是 XOR 不雪崩 + GHASH tag 不匹配即拒绝），从不交付"一堆翻转的明文"。

### 1.3 v3 新增目标
- 按**内容类别**消除小文件空间浪费，同时提供**可配置的纠错强度**：

| 内容类别 | 示例 | scheme | 空间 | 纠错 |
|---|---|---|---|---|
| 可重拉小文件 | 缩略图/元数据/字幕 | `gcm-only` | ~1× | 检测（GCM），损坏→重拉 |
| 不可重拉小文件（<1MB）| 导入的独有小文件/小视频 | `rs-strong` | ~3.15× | RS(32,64) **66.7%** 散落损坏 |
| 视频（≥1MB 独有）| p91 主视频 | `rs-dual` | 2.37~3.16× | 块内 33% + 组内 50% blob |

- **恢复能力不降级**：rs-strong 66.7% 容错 > v2 块内 33%；rs-dual 沿用 v2 双层。

## 2. v2 的问题（小文件浪费 + p91 真实数据）

v2 两个固定参数导致小文件浪费：
- **根因 A**：`chunkPlainSize = 1,048,528`（1MB 块）→ 1B~1MB 文件都占 1 个 1.58MB data blob。
- **根因 B**：文件级 parity 固定 `M2=64`/组 → 末组 1 块也发 64 个 parity blob。

叠加浪费（`TotalBlobCount(C) = (G-1)*192 + kLast + 64`）：

| 文件明文 | 块数 | 总 blob | 落盘 | 浪费 |
|---|---|---|---|---|
| 1 KB | 1 | 65 | 102.6MB | ~100,000× |
| 100 KB | 1 | 65 | 102.6MB | ~1000× |
| 1 MB | 1 | 65 | 102.6MB | ~100× |
| 128 MB（满组）| 128 | 192 | 303MB | 2.37×（正常）|

**p91 库实测（2026-09）**：838 个视频，真实 ≤1MB 文件仅 5 个（480KB~988KB），
14 个"0-16KB"条目全是爬虫元数据占位（bytes=0，无文件）。v2 对这 5 个小文件的浪费
≈ 5×102.6MB ≈ 513MB，占总库 46.9GB 的 ~1.1%——**单文件比例是 100×~100000×，聚合仅 1%**。
但用户确认：后续会把缩略图/元数据/字幕等 KB 级文件**批量加密入库**（几百上千个），
届时聚合浪费将爆炸 → v3 必须治。

## 3. 三类别容器总览

```
容器文件 = [scheme 特定正文] + [尾部 manifest trailer（同 v2 结构）]
manifest 增加 scheme 字段；每种 scheme 有独立布局与恢复语义
```

| scheme | 正文结构 | 恢复语义 |
|---|---|---|
| `gcm-only` | [magic+nonce][GCM密文+tag] | GCM.Open 失败 → 检测到损坏 → 调用方重拉 |
| `rs-strong` | [32 数据 shard + 64 校验 shard = 96 槽] | 任意 ≤64/96 槽坏 → RS(32,64) 重建 → GCM 终审 |
| `rs-dual` | v2 块结构 + v3.0 自适应 parity | 块内 ≤128 shard + 组内 ≤64 blob 双层 |

### 3.1 类别选择规则（写器 API）
调用方声明**内容是否可重拉 + 访问模式**，尺寸自动定 scheme：

```go
// NewWriter(dst, key, WithRePull())                 → gcm-only（可重拉小内容）
// NewWriter(dst, key, WithSeekable())               → rs-dual，M2 上限 64（默认，随机播放）
// NewWriter(dst, key, WithArchival(m2))             → rs-dual，M2 上限 m2（如 32/16，纯归档无随机播放）
// NewWriter(dst, key)                               → 按尺寸自动：plainSize < 1MB → rs-strong，否则 rs-dual(seekable)
```

- `WithRePull()`：缩略图/元数据/字幕等可从源站重拉的内容（gcm-only，~1×）。
- `WithSeekable()`：需要块级随机访问（视频 Range 播放）→ rs-dual，M2=64（区域容错 50%）。
- `WithArchival(m2)`：纯归档、无需随机播放 → rs-dual 降低文件级 parity（空间 1.98×@m2=32 / 1.78×@m2=16），
  块内 33% 散落容错不变，仅区域容错降为 m2/128。**随机访问能力在 rs-dual 格式里是免费的**
  （块结构为内存流式所必需），"不需要随机播放"真正解锁的是降低 M2 的空间收益。
- 默认：不可重拉内容按体积自动分档（<1MB → rs-strong，≥1MB → rs-dual seekable）。
- rs-strong 无硬性尺寸上限（K+M=96 恒定，shardSize 随文件增长），1MB 分界是**空间**考量：
  rs-dual 满组 2.37× 优于 rs-strong 3.15×，且大文件散落损坏需要组级组合修复。
- 双层 RS 的设计澄清（用户问"双层优势"）：双层的价值不只是随机访问+修复局部化，还有
  ① 内存流式（单 blob = 3.15× RAM，8GB A733 上限 ~1-2GB 文件，大文件必须分块）与
  ② 区域恢复（组层跨块重建死块，无组层则成片坏死不可恢复）。故大文件即使纯归档仍用 rs-dual
  （分块流式+组层），只是可接受更低的 M2。

## 4. scheme: gcm-only（可重拉小文件）

### 4.1 布局
```
[4B magic "SVGO"][12B nonce][GCM密文+tag ((plainSize+16)B)] [尾部 trailer]
```

### 4.2 加密
- key = HKDF(master, fileID, "secvault/gcm/v1")；nonce 12B 随机，AAD = 16B 头部（magic+nonce）。
- 无 RS、无 shard tag、无分块——整个文件一个 GCM 单元。

### 4.3 恢复
- GCM.Open 成功 → 明文可信。失败 → 检测到损坏/篡改 → **调用方重拉**（本类别定义如此）。
- 空间 ~1×（+16B tag + trailer）。

### 4.4 适用
缩略图/元数据/字幕等可从 p91 站点重拉的内容。损坏成本 = 一次网络请求，不值得付冗余空间。

## 5. scheme: rs-strong（不可重拉小文件 <1MB）

### 5.1 参数（固定，manifest 冗余记录）
```
K = 32        数据 shard（固定）
M = 64        校验 shard（固定，M = 2K）
shardSize = ceil((HeaderSize + plainSize + TagSize) / K)   // 变长 shard，随文件尺寸缩放
槽数 = 96，每槽 = [shardSize B 载荷][16B SHA-256 截断 tag]
落盘 = 96 × (shardSize + 16)
```

### 5.2 布局
```
RS 数据区（K×shardSize B）= chunkHeader(32B) || GCM密文+tag ((plainSize+16)B) || 零填充
→ 切成 32 个数据 shard → RS(32,64) 生成 64 个校验 shard
落盘 96 槽，每槽 = [shardSize B 载荷][16B tag]
```
- chunkHeader 复用 v2 32B 结构（magic SVC1 + 块序号 + plainLen + nonce），GCM AAD = 块头。
- 文件级 RS **不适用**（单 blob 无组概念）；恢复全部靠块内 RS(32,64)。

### 5.3 恢复能力（等比例收缩，非降级）
| plainSize | shardSize | 落盘 | 倍数 | 容错 |
|---|---|---|---|---|
| 1 KB | 34 | ~4.8KB | 4.7× | 任意 64/96 槽坏 = 66.7% |
| 100 KB | 3203 | ~309KB | 3.09× | 66.7% |
| 1 MB | 32770 | ~3.15MB | 3.15× | 66.7% |

- **容错 66.7%**：100KB 文件被毁 60KB+ 仍整文件恢复，远超 bit rot 量级。
- 绝对意义：K=32 固定 + shardSize 缩放 → 小文件粒度 32B（1KB 文件分 32 片），
  大文件粒度 32KB（1MB 文件分 32 片），任意位置损坏都在 66.7% 容错内。
- tag 开销随 shardSize 反比：1KB 文件 96×16B=1.5KB tag（150%），绝对量可忽略。

### 5.4 为什么否决 v3.1 变长末块和 mirror（设计史）
- **v3.1 变长末块**（KLast=ceil(plain/4KB), MLast=KLast/2）：1KB→8×、100KB→3.12×，
  容错 33%~50%，**不如** rs-strong（1KB→4.7× 但 66.7% 且实现更简单——无变长布局，
  恒 96 槽）。变长 blob 让 layout 偏移数学从等差数列变前缀和，复杂度不值得。
- **mirror（GCM×2）**：2× 空间，1-of-2 块级存活。但 GCM 是文件粒度全有全无——
  两副本各有 1 bit 不同位置损坏 → 两副本 GCM 都失败 → **整文件丢**（per-block GCM 可缓解
  但块粒度=文件粒度对小文件无效）。用户选择 rs-strong（66.7% 单副本散落修复）替代。

## 6. scheme: rs-dual（视频 ≥1MB，v2 + v3.0 自适应 parity）

### 6.1 = v2 格式 + 自适应文件级 parity（M2 可配置上限）
v2 布局完全不变（块内 RS(256,128) + 文件级 RS(128,64)），唯一改动：文件级 parity 数可配置，
末组再叠加 1:1 上限：

```
M2Cap   = 写器声明（seekable=64 / archival=32 或 16），manifest 记录
末组 parity 数 = min(M2Cap, kLast)   // 1:1 上限；满组 = M2Cap
```

- 1 块文件 → 1 data + 1 parity = 2 blob（v2 为 1+64=65 blob）
- 满组 128 块 + M2Cap=64 → 128+64 = 192（同 v2，不变）
- 满组 128 块 + M2Cap=32 → 128+32 = 160（archival，1.98×）
- M2Cap=16 → 128+16 = 144（archival 更省，1.78×）

### 6.2 layout 数学（v3.0）
```go
// layout 包新增纯函数（M2Cap 作为参数；v2 读路径用 M2Cap=64）
func GroupParityCount(m2cap, chunkCount int64) int64 {
    if chunkCount == 0 { return 0 }
    return min(m2cap, LastGroupChunks(chunkCount))
}
func TotalBlobCount(m2cap, chunkCount int64) int64 {
    g := GroupCount(chunkCount)
    if g == 0 { return 0 }
    kLast := LastGroupChunks(chunkCount)
    return (g-1)*(FileGroupChunks+m2cap) + kLast + min(m2cap, kLast)
}
func DataBlobOffset(m2cap, i, chunkCount int64) int64 {
    g := i / FileGroupChunks
    gLast := GroupCount(chunkCount) - 1
    parityCount := m2cap
    if g == gLast { parityCount = min(m2cap, LastGroupChunks(chunkCount)) }
    return g*(FileGroupChunks+m2cap)*BlobDiskSize + parityCount*BlobDiskSize + (i%FileGroupChunks)*BlobDiskSize
}
```
- `ParityBlobOffset` 需增加 `m2cap`/`chunkCount` 参数（判断组 parity 数）；纯函数，调用方易改。
- `codec.File(k)` → `File(k, m)`，cache key 改 `(k,m)`，支持 `m ≤ min(m2cap, k)`。
- v2 文件读路径 = m2cap=64 的特例（v2 末组也发 64 parity，与 m2cap=64 + 1:1 上限规则不符 →
  需按 manifest 版本分支：v2 用"末组恒 64"，v3 用"min(m2cap, kLast)"）。

### 6.3 恢复能力（v2 → v3.0）
| 场景 | v2 | v3.0 |
|---|---|---|
| 1KB 文件零星坏 ≤128 shard | 块内 RS 修 | 不变 |
| 1KB 文件整块死 | 64 parity 救 | 1 parity 救（1:1 冗余反更强）|
| 满组 128 块整块死 ≤64 | 64 parity 救 | 不变 |
| GCM 终审 | ✅ | ✅ |

### 6.4 空间（v3.0 自适应 parity 后）
| 块数 | 落盘 | 倍数 |
|---|---|---|
| 1（≤1MB）| 2 blob = 3.16MB | 3.16× |
| 64 | 128 blob | 3.16× |
| 128（满组）| 192 blob = 303MB | 2.37× |

## 7. manifest 变更

```go
type Manifest struct {
    // ... v2 字段不变（v/k/m/k2/m2/ss/cp/cc/ps）...
    Scheme string `json:"sc"` // "gcm" | "rs-strong" | "rs-dual"
    // rs-strong 冗余记录（K/M 固定可省略；记录以支持前向校验）
    KStrong int `json:"ks,omitempty"` // =32
    MStrong int `json:"ms,omitempty"` // =64
}
```

- `Validate`：按 scheme 分派尺寸一致性校验。
  - gcm-only：size == 16 + plainSize + 16 + trailerLen。
  - rs-strong：size == 96×(shardSize+16) + trailerLen，shardSize = ceil((32+plainSize+16)/32)。
  - rs-dual：size == TotalBlobCount(cc)×BlobDiskSize + trailerLen（v3.0 公式）。
- 截断/追加即刻检出（同 v2）。

## 8. 版本与兼容

- trailer `version`：v2=2，v3=3。v3 reader 同时支持 v2（旧数学）与 v3（按 scheme 分派）。
- v2 writer 停用；v2 文件永久可读可 scrub（legacy 路径）。
- p91 现有 722 个已 vault 视频（v2）：**不强制迁移**。它们大多 ≥1MB 走满组/近满组，
  v3.0 自适应 parity 对满组无增益，重打无收益。新写视频用 v3 rs-dual。
- 可选 v2→v3 重打包工具（未来 CLI）：`io.Copy(v3writer, v2reader)`，因 secvault 是流式语义。

## 9. 迁移路径

1. **不做格式迁移**：v2 视频保持 v2（可读可 scrub），新写全部 v3。
2. p91 接入（未来）：缩略图/元数据/字幕用 `WithRePull()` → gcm-only；
   导入的独有小文件 → 默认 rs-strong；新视频 → rs-dual。
3. 观察一个 scrub 周期后，按真实损坏模式微调 rs-strong/rs-dual 分界与强度。

## 10. 实现阶段

### 阶段 1：v3.0 自适应 parity（rs-dual，1~2 周）
1. `layout`：新增 `LastGroupParity`、改 `TotalBlobCount`/`DataBlobOffset`/`ParityBlobOffset`（带 chunkCount 参数）。
2. `codec`：`File(k, m)` 支持 variable m，cache key 改 `(k,m)`。
3. `format`：manifest 加 `Scheme`；`Validate` 用 v3.0 尺寸公式。
4. `engine`：pipeline 末组 parity 数按 `LastGroupParity`；reader/scrub 按 v3.0 数学定位。
5. 单测：末组 kLast=1/64/128 边界 + 恢复对照。

### 阶段 2：gcm-only + rs-strong（1~2 周，比 v3.1 变长末块简单——单 blob 无流水线）
1. `layout`：gcm-only/rs-strong 布局常量与尺寸函数。
2. `codec`：新增固定 RS(32,64) 编码器（warmup 一次）；shardSize 变长参数化。
3. `format`：scheme 分派 + 两种正文头（SVGO/SVC1）。
4. `engine`：gcm-only 读=单次 GCM.Open；rs-strong 读=96 槽 tag 验 → RS(32,64) 重建 → GCM 终审。
5. `scrub`：rs-strong 逐槽 tag 修复 + 回写；gcm-only 无修复（损坏即报，交调用方重拉）。
6. 单测：rs-strong 损坏矩阵（坏 1~64 槽逐步逼近极限）、gcm-only 篡改检测、尺寸边界。
7. 基准：rs-strong 编码吞吐（预期远高于 rs-dual——单 blob 无流水线，GF 总量 = 2×plainSize）。

### 阶段 3（可选）：p91 接入
- 缩略图/元数据抓取 + `WithRePull()` 入库（gcm-only）；小文件类别自动分档。

## 11. 风险与未决

### 11.1 rs-strong 单 blob 无"整块级"兜底
- 若 rs-strong 文件所在区域成片损坏（>66.7% 槽坏）→ 不可恢复。无第二副本。
- 缓解：本类别 <1MB 且按 1 个 Quark 对象存储，对象级损坏概率低；可重拉内容走 gcm-only 不占此档。
- 未决：是否需要"rs-strong + 2 独立容器"（对象级存活）？超出 v2"介质报废不设防"范围，暂缓。

### 11.2 rs-strong tag 开销（小文件）
- 1KB 文件 96×16B=1.5KB tag（150%），绝对量 ~1.5KB 可忽略。若未来大量 1KB 级不可重拉文件，
  可降 tag 至 8B（碰撞 2^-64 仍足够定位意外损坏）或 K 降到 16。

### 11.3 codec cache
- rs-strong 恒 (32,64) 单配置；rs-dual File(k,m) 按 (k,m) 缓存（m≤64 有限集）。无膨胀风险。

### 11.4 分界 T=1MB 的可调性
- 按 p91 实测（5 个真实小文件均 <1MB）暂定 1MB。若出现 1-4MB 的不可重拉文件且空间敏感，
  可把 rs-strong 的 shardSize 上限再放宽（K=32 无硬上限，仅空间 3.15× vs rs-dual 2.37× 权衡）。
