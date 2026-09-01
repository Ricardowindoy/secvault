// Package layout 定义 secvault 的全部布局常量与版本感知的偏移/计数数学。
// 零依赖、纯函数——本包不做任何 I/O 与序列化。
//
// 布局数学统一经 Spec 计算：所有偏移与 blob 计数都由 Spec 的方法给出，
// v2/v3 的组布局差异（parity-first vs data-first、恒 64 parity vs M2Cap 上限）
// 集中收敛于 Spec 一处，调用点无需按版本分支。
// 组数/末组块数等版本无关的纯计数仍为包级函数。
//
// v2 组内布局（parity 在前，无屏障写入的关键）：
//
//	[组g: 64 个 parity blob | kData 个数据 blob] … [尾部 manifest trailer]
package layout

// RS 布局常量（v2 固定，manifest 中冗余记录用于一致性校验）。
const (
	ShardSize     = 4096 // 单 shard 载荷
	TagSize       = 16   // 每 shard 截断 SHA-256
	DataShards    = 256  // 块内数据 shard
	ParityShards  = 128  // 块内校验 shard
	ShardsPerBlob = DataShards + ParityShards

	HeaderSize     = 32                                     // 块头
	ChunkPlainSize = DataShards*ShardSize - HeaderSize - 16 // 每块明文容量 1,048,528
	BlobPlainSize  = DataShards * ShardSize                 // RS 数据区 1,048,576
	SlotSize       = ShardSize + TagSize                    // 落盘槽 4112
	BlobDiskSize   = int64(ShardsPerBlob) * int64(SlotSize) // 1,579,008

	FileGroupChunks   = 128 // 文件级每块数
	FileParityShards  = 64
	BlobsPerFullGroup = int64(FileGroupChunks + FileParityShards)

	NonceSize     = 12
	MasterKeySize = 32
)

// GroupCount 组数 = ceil(C/128)。
func GroupCount(chunkCount int64) int64 {
	if chunkCount == 0 {
		return 0
	}
	return (chunkCount-1)/FileGroupChunks + 1
}

// LastGroupChunks 末组块数（1..128）。
func LastGroupChunks(chunkCount int64) int64 {
	return chunkCount - (GroupCount(chunkCount)-1)*FileGroupChunks
}

// DataChunksInGroup 组 g 的数据块数（末组为 kLast，其余 128）。
func DataChunksInGroup(g, chunkCount int64) int64 {
	if g == GroupCount(chunkCount)-1 {
		return LastGroupChunks(chunkCount)
	}
	return FileGroupChunks
}

// Spec 是容器级布局参数：格式版本 + 文件级 parity 上限。
// v2：parity-first 组布局，每组恒 64 parity（含末组）；
// v3：data-first 组布局，每组 parity = min(M2Cap, kData)。
// 所有偏移/计数经 Spec 方法计算，版本差异集中于此。
type Spec struct {
	Version int
	M2Cap   int64
}

// SpecV2 当前 v2 语义（parity-first、恒 64 parity）。
func SpecV2() Spec { return Spec{Version: 2, M2Cap: FileParityShards} }

// SpecV3 未来 v3 语义（data-first、parity 上限 m2cap）。本次不产出 v3 文件，仅结构就绪。
func SpecV3(m2cap int64) Spec { return Spec{Version: 3, M2Cap: m2cap} }

// groupSpan 组内总槽位（数据槽 + parity 槽）。
// v2 = BlobsPerFullGroup(192)；v3 = FileGroupChunks + M2Cap。
func (s Spec) groupSpan() int64 {
	if s.Version >= 3 {
		return FileGroupChunks + s.M2Cap
	}
	return BlobsPerFullGroup
}

// GroupParity 组 g 的 parity blob 数。
// v2 恒 FileParityShards(64)（含末组）；v3 = min(M2Cap, DataChunksInGroup(g, chunkCount))。
func (s Spec) GroupParity(g, chunkCount int64) int64 {
	if s.Version >= 3 {
		return min(s.M2Cap, DataChunksInGroup(g, chunkCount))
	}
	return FileParityShards
}

// DataBlobOffset 数据 blob i 的文件偏移。
// v2：组首 64 个 parity 槽之后；v3：组首（data-first，不依赖 kLast，可流式写）。
func (s Spec) DataBlobOffset(i int64) int64 {
	g := i / FileGroupChunks
	base := g * s.groupSpan() * BlobDiskSize
	if s.Version >= 3 {
		return base + (i%FileGroupChunks)*BlobDiskSize
	}
	return base + FileParityShards*BlobDiskSize + (i%FileGroupChunks)*BlobDiskSize
}

// ParityBlobOffset 组 g 第 q 个 parity blob 偏移；kData 为该组数据块数。
// v2：组首（q*BlobDiskSize）；v3：数据之后（kData*BlobDiskSize + q*BlobDiskSize）。
func (s Spec) ParityBlobOffset(g, kData, q int64) int64 {
	base := g * s.groupSpan() * BlobDiskSize
	if s.Version >= 3 {
		return base + kData*BlobDiskSize + q*BlobDiskSize
	}
	return base + q*BlobDiskSize
}

// TotalBlobCount 数据 + parity 总 blob 数。
func (s Spec) TotalBlobCount(chunkCount int64) int64 {
	g := GroupCount(chunkCount)
	if g == 0 {
		return 0
	}
	kLast := LastGroupChunks(chunkCount)
	if s.Version >= 3 {
		return (g-1)*s.groupSpan() + kLast + min(s.M2Cap, kLast)
	}
	return (g-1)*s.groupSpan() + kLast + FileParityShards
}
