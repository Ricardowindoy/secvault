// Package layout 定义 secvault v2 的全部布局常量与纯偏移数学。
// 零依赖、纯函数——本包不做任何 I/O 与序列化。
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

// BlobOffset 数据块 i 的文件偏移（v2：组首 parity 之后）。
func BlobOffset(chunkIndex int64) int64 {
	return (chunkIndex/FileGroupChunks)*BlobsPerFullGroup*BlobDiskSize +
		FileParityShards*BlobDiskSize + (chunkIndex%FileGroupChunks)*BlobDiskSize
}

// ParityBlobOffset 组 g 第 p 个 parity blob 偏移（组内局部可算，不依赖总块数）。
func ParityBlobOffset(g, p int64) int64 {
	return g*BlobsPerFullGroup*BlobDiskSize + p*BlobDiskSize
}

// TotalBlobCount 数据 + parity 总 blob 数。
func TotalBlobCount(chunkCount int64) int64 {
	g := GroupCount(chunkCount)
	if g == 0 {
		return 0
	}
	return (g-1)*BlobsPerFullGroup + LastGroupChunks(chunkCount) + FileParityShards
}
