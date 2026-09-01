// Package codec 封装 Reed-Solomon 编解码器的构造、缓存与窗口视图工具。
// 单一实例化点：intra（256+128）与 file（k,m）可变校验数编码器只经 Cache 构造（含 warmup），
// 消灭历史上 writer/core 各持一套的重复。
package codec

import (
	"fmt"
	"sync"

	"github.com/klauspost/reedsolomon"

	"secvault/internal/layout"
)

// Cache RS 编码器缓存（并发安全）。
// files 按 (k, m) 二元组键控：map[[2]int] 语义清晰且天然无碰撞
// （文件级编码器由数据片数 k 与校验片数 m 两个维度共同唯一确定）。
// strong 是 rs-strong scheme 的固定 RS(32,64) 编码器（构造时一并 warmup）。
type Cache struct {
	mu     sync.Mutex
	intra  reedsolomon.Encoder
	strong reedsolomon.Encoder
	files  map[[2]int]reedsolomon.Encoder
}

// NewCache 构造缓存并完成 intra / strong 编码器 warmup
// （触发 RS 库延迟初始化，避免多 worker 首次并发 Encode 的内部竞态）。
func NewCache() (*Cache, error) {
	intra, err := reedsolomon.New(layout.DataShards, layout.ParityShards)
	if err != nil {
		return nil, fmt.Errorf("secvault: intra codec: %w", err)
	}
	if err := warmupN(intra, layout.ShardsPerBlob); err != nil {
		return nil, fmt.Errorf("secvault: intra warmup: %w", err)
	}
	strong, err := reedsolomon.New(layout.KStrong, layout.MStrong) // rs-strong 固定 RS(32,64)
	if err != nil {
		return nil, fmt.Errorf("secvault: strong codec: %w", err)
	}
	if err := warmupN(strong, layout.StrongSlots); err != nil {
		return nil, fmt.Errorf("secvault: strong warmup: %w", err)
	}
	return &Cache{intra: intra, strong: strong, files: map[[2]int]reedsolomon.Encoder{}}, nil
}

// Intra 返回块内 RS(256,128) 编码器。
func (c *Cache) Intra() reedsolomon.Encoder { return c.intra }

// Strong 返回 rs-strong 固定 RS(32,64) 编码器（warmup 过）。
// 变长 shardSize 对 reedsolomon 透明（shard 为任意等长 []byte），无需单独实例化。
func (c *Cache) Strong() reedsolomon.Encoder { return c.strong }

// File 返回文件级 RS(k, m) 编码器（按 (k, m) 缓存）。
// k ∈ [1, FileGroupChunks]，m ∈ [1, FileParityShards]。
// 注意：不设 m ≤ k 守卫——v2 格式末组恒写 FileParityShards(64) 个 parity blob
// （即使 kLast < 64，如 RS(40,64) 合法）；v3 的 1:1 上限（min(M2Cap,kData)）
// 由 engine 侧 Spec.GroupParity 保证，codec 只做参数范围校验。
func (c *Cache) File(k, m int) (reedsolomon.Encoder, error) {
	if k < 1 || k > layout.FileGroupChunks {
		return nil, fmt.Errorf("secvault: bad file-level k=%d", k)
	}
	if m < 1 || m > layout.FileParityShards {
		return nil, fmt.Errorf("secvault: bad file-level m=%d (1<=m<=FileParityShards)", m)
	}
	key := [2]int{k, m}
	c.mu.Lock()
	defer c.mu.Unlock()
	if rs, ok := c.files[key]; ok {
		return rs, nil
	}
	rs, err := reedsolomon.New(k, m)
	if err != nil {
		return nil, fmt.Errorf("secvault: file codec k=%d m=%d: %w", k, m, err)
	}
	c.files[key] = rs
	return rs, nil
}

// warmup 用默认 shard 数（ShardsPerBlob=384）预热编码器。
func warmup(enc reedsolomon.Encoder) error {
	return warmupN(enc, layout.ShardsPerBlob)
}

// warmupN 用 n 个 shard 预热编码器（触发 RS 库延迟初始化）。
// shard 总数不同（intra=384 / strong=96）需分开构造预热缓冲。
func warmupN(enc reedsolomon.Encoder, n int) error {
	shards := make([][]byte, n)
	for i := range shards {
		shards[i] = make([]byte, 64)
	}
	return enc.Encode(shards)
}

// ExtractPayloads 从 (payload+tag) 交错缓冲中抽出 cols 个连续列载荷。
// 注意：步长是 SlotSize（4112，含 16B tag），不是 ShardSize（4096）。
// 用错步长会抽出错位的列，导致所有文件级 RS 重建系统性错误。
func ExtractPayloads(raw []byte, cols int) []byte {
	out := make([]byte, cols*layout.ShardSize)
	for c := 0; c < cols; c++ {
		copy(out[c*layout.ShardSize:], raw[c*layout.SlotSize:c*layout.SlotSize+layout.ShardSize])
	}
	return out
}

// SliceWindow 从连续载荷缓冲中切出第 j0 列起 wc 个 4KB 列的拼接视图（零拷贝）。
// 用于文件级 RS：窗口对齐 shard 边界时每个窗口恰好落在单一缓冲的连续区段。
func SliceWindow(buf []byte, j0, wc int) []byte {
	off := j0 * layout.ShardSize
	return buf[off : off+wc*layout.ShardSize]
}
