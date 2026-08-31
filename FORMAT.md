# secvault 格式规范 v2（方案 C）

单文件视频加密+纠错容器。设计目标：防篡改（AEAD 认证）+ 防 bit 反转可恢复（双层 Reed-Solomon）
+ 支持月度人工巡检（scrub 就地修复）。**无副本设计**，安全锚点唯一：AES-256-GCM tag。

## 威胁模型

- 意外损坏：SD/eMMC bit rot、坏扇区、传输误码 → RS 纠错恢复，GCM 终审。
- 恶意篡改：任何超过 RS 纠错能力的篡改 → GCM.Open 拒绝（2^-32 级漏检）。
- 介质整体报废：**不设防**（无副本），需外部冷备。

## 固定参数（v1）

| 参数 | 值 | 说明 |
|---|---|---|
| shardSize | 4096 | RS shard 载荷字节数 |
| tagSize | 16 | 每 shard 截断 SHA-256（非密钥，仅定位意外损坏） |
| K / M（块内） | 256 / 128 | 每块 256 数据 shard + 128 校验 shard |
| headerSize | 32 | 块头（纳入 RS 保护域 + GCM AAD） |
| chunkPlainSize | 1,048,528 | 每块明文容量 = 256×4096 − 32 − 16 |
| blobDiskSize | 1,579,008 | 块落盘尺寸 = 384 × (4096+16) |
| K2 / M2（文件级） | 128 / 64 | 每 128 块一组，64 个文件级校验 blob |
| 主密钥 | 32B | AES-256；HKDF-SHA256 派生子密钥 |

## 布局（v2：组内 parity 在前）

```
[组0: 64 个 parity blob | 128 个数据 blob][组1: 64 parity | 128 数据]…[末组: 64 parity | kLast 数据]
[尾部 manifest trailer]
```

- 块 i 偏移 = `(i/128)*192*blobDiskSize + 64*blobDiskSize + (i%128)*blobDiskSize`
- 组 g 第 p 个 parity blob 偏移 = `g*192*blobDiskSize + p*blobDiskSize`（**组内局部可算，不依赖总块数**）
- 组数 G = ceil(C/128)；末组 kData = C − (G−1)*128（1..128，文件级 RS 动态建码）
- 总 blob 数 = (G−1)*192 + kLast + 64

**v1→v2 动机**：v1 数据在前的布局中，组 g+1 的数据物理位置排在组 g 的 parity 之后，
写盘必须等 parity 完成（组屏障）；v2 把 parity 挪到组首，两者位置解耦，
写入器的数据写与 parity 后台计算完全并行（实测 +12%，与编码 workers 抢内存带宽成为新地板）。

### 块（blob）内部

```
RS 数据区（1,048,576 B）= chunkHeader(32B) || GCM密文+tag((plainLen+16)B) || 零填充
→ 切成 256 个 4KB 数据 shard → RS(256,128) 生成 128 个校验 shard
落盘 384 个槽，每槽 = [4096B 载荷][16B SHA-256 截断 tag]
```

chunkHeader（32B，明文但受 shard tag + GCM AAD 双重保护）：
```
[0:4]   "SVC1"
[4:12]  块序号 uint64 BE
[12:20] plainLen uint64 BE（末块 < chunkPlainSize）
[20:32] nonce 12B = 4B 随机前缀 || 8B 块序号 BE
```

- GCM：AES-256-GCM，key = HKDF(master, salt=fileID, "secvault/chunk/v1")，
  nonce 如上，**AAD = 32B 块头**。每 (key,nonce) 只加密 1MB，nonce 全局唯一由序号保证。
- 文件级 RS：把每个 blob 的 384 个 4KB 载荷列当作独立列，对组内 kData 个 blob
  做 RS(kData, 64)。parity blob 与数据 blob 同构（384 槽，每槽带 tag）。
  RS 对「拼接的 w 列」编码等价于逐列编码（系数与位置无关），实现按 32 列窗口流式处理。

### 尾部 trailer（40 + L + 4 字节）

```
[0:4]   "SVLT"
[4]     version = 1
[5]     flags
[6:8]   保留
[8:24]  fileID 16B（HKDF 盐，非机密）
[24:36] manifest GCM nonce 12B
[36:40] manifest 密文长度 L uint32 BE
[40:]   manifest JSON 的 GCM 密文+tag
[+4]    CRC32C（覆盖此前全部字节）
```

manifest（JSON，key = HKDF(master, fileID, "secvault/manifest/v1")）：
`{v, k, m, k2, m2, ss, cp, cc(块数), ps(明文总长)}`。
Open 时强校验 size == totalBlobCount(cc)*blobDiskSize + trailerLen → 截断/追加即刻检出。

## 读路径（任意块）

1. 顺序读整 blob（1.58MB），逐槽验 tag → 坏槽置 nil（erasure）；
2. 坏槽数 ≤128 → RS(256,128) 重建 → 重建载荷须通过其 tag；
3. 仍失败 → 文件级：组内按 32 列窗口 RS(kData,64) 重建整个 blob
   （输入列逐槽验 tag，坏列也作 erasure，≤64 可容）；
4. 解析块头 → GCM.Open（AAD=块头）→ 明文。任何一步失败 → 该块不可恢复。

## 巡检（scrub）

1. manifest 对账（Open 的 size 一致性 + 块数）；
2. 逐块 pass1：tag 验证 → RS 块内修复 → **WriteAt 回写修复槽** → GCM.Open 深度校验；
3. pass2：块内救不活的块走文件级整块重建并整 blob 回写；
4. pass3（可选 RebuildParity）：重算文件级 parity 并回写坏槽；
5. 报告：清洁/修复/重建/丢失块清单。修复来源是纠错冗余本身，无需副本。

## 明确的边界（无副本代价）

- 同组 >64 块整体坏死 → 该组超出部分永久丢失（scrub 报告精确列出）；
- 介质报废 → 全部丢失。对策：每月 scrub 后整目录 rsync 冷备到异品牌盘。

## 写入语义与流水线（实现注记）

- Writer 为三段流水：主 goroutine 切块 → workers 并行 GCM+块内 RS+拼装 → 落盘 goroutine 按序写 blob（组级 parity 屏障 + trailer 也在该 goroutine）。
- `Write` 返回 ≠ 已落盘（流水线异步），错误延后至后续 `Write`/`Close`；**必须调用 `Close`**，否则流水线 goroutine 泄漏。
- 非并发安全：单 goroutine 顺序调用 `Write`/`Close`。
- 旋钮：`WithWorkers(n)`（默认 4）、`WithInflight(n)`（默认 16；每 in-flight 块约 2.6MB 内存，上限 16+4 块 ≈ 52MB）。
- A733 实测：全核（不 taskset）w4-f16 最优 ~52MB/s；`taskset -c 6,7` 钉大核反而 33-40MB/s（小核参与编码的并行收益 > 单核速度差）。
- shard tag 维持 16B 截断 SHA-256（CRC32C 替换评估过：省 1.2ms/块，未采纳）。
