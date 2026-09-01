package engine

// rs-strong scheme 读写后端（v3 批次2，FORMAT-v3.md §5 / DESIGN-v3-phase2 §2.8）：
// 不可重拉小文件的单 blob 布局——整个文件一个 GCM 单元，RS 数据区 =
// 32B 块头(SVC1) || GCM 密文+tag || 零填充，切 32 个数据 shard 经 RS(32,64)
// 生成 64 个校验 shard，96 槽顺序落盘（每槽 [shardSize B 载荷][16B ShardTag]）。
//
// 与 gcm-only 的差异：shardSize 随 plainSize 变长（ceil((32+ps+16)/32)），nonce 纯随机
//（单 blob 无块序号可编码）；密钥复用 chunk 域（"secvault/chunk/v1"）与 32B 块头，
// 与 rs-dual 的块加密同源。写入侧实现 SmallFileSink（与 gcmOnlySink 同构的缓冲语义）。

import (
	"fmt"
	"io"

	"secvault/internal/codec"
	"secvault/internal/crypto"
	"secvault/internal/errors"
	"secvault/internal/format"
	"secvault/internal/layout"
)

// ---- rs-strong 写入后端 ----

// strongSink 缓冲全部明文，Drain 时一次性 GCM 加密 + RS(32,64) 编码 + 96 槽落盘。
type strongSink struct {
	dst    io.ReadWriteSeeker
	aead   crypto.AEAD // HKDF(master, fileID, "secvault/chunk/v1") —— 复用 chunk 域
	codecs *codec.Cache
	buf    []byte // 明文缓冲（增长式）
}

// NewStrongSink 构造 rs-strong 写入后端（顶层 Writer 经 SmallFileSink 接口持有）。
func NewStrongSink(dst io.ReadWriteSeeker, aead crypto.AEAD, codecs *codec.Cache) SmallFileSink {
	return &strongSink{dst: dst, aead: aead, codecs: codecs}
}

func (s *strongSink) Write(p []byte) (int, error) {
	s.buf = append(s.buf, p...)
	return len(p), nil
}

// Drain（FORMAT-v3.md §5.2）：
//  1. nonce = 随机 12B（单 blob，无块序号可编码，纯随机）；
//  2. hdr = ChunkHeader{Index:0, PlainLen:len(buf), Nonce}.Marshal()（复用 SVC1 32B 块头）；
//  3. ct = aead.Seal(nonce, buf, hdr)（AAD = 块头）；
//  4. dataArea = hdr || ct || 零填充到 KStrong×shardSize；
//  5. 切 32 个数据 shard（连续切片零拷贝视图），RS(32,64) 编码出 64 个校验 shard；
//  6. 96 槽顺序写：每槽 [shardSize B 载荷][16B ShardTag]，偏移 0 起
//     （trailer 由顶层 Writer 在 StrongPayloadSize 偏移处追加）。
func (s *strongSink) Drain() (int64, error) {
	plainSize := int64(len(s.buf))
	nonce, err := crypto.RandomBytes(layout.NonceSize)
	if err != nil {
		return 0, err
	}
	hdr := (&format.ChunkHeader{Index: 0, PlainLen: len(s.buf), Nonce: nonce}).Marshal()
	ct := s.aead.Seal(nil, nonce, s.buf, hdr)

	shardSize := layout.StrongShardSize(plainSize)
	dataArea := make([]byte, shardSize*layout.KStrong) // 零填充就位
	copy(dataArea, hdr)
	copy(dataArea[len(hdr):], ct)

	shards := make([][]byte, layout.StrongSlots)
	for i := 0; i < layout.KStrong; i++ {
		shards[i] = dataArea[int64(i)*shardSize : int64(i+1)*shardSize] // 零拷贝数据视图
	}
	for i := layout.KStrong; i < layout.StrongSlots; i++ {
		shards[i] = make([]byte, shardSize) // 校验 shard 预分配，Encode 填充
	}
	if err := s.codecs.Strong().Encode(shards); err != nil {
		return 0, fmt.Errorf("secvault: strong encode: %w", err)
	}

	disk := make([]byte, 0, layout.StrongSlots*(shardSize+int64(layout.TagSize)))
	for i := 0; i < layout.StrongSlots; i++ {
		disk = append(disk, shards[i]...)
		disk = append(disk, crypto.ShardTag(shards[i])...)
	}
	if _, err := s.dst.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}
	if n, err := s.dst.Write(disk); err != nil {
		return 0, err
	} else if n != len(disk) {
		return 0, io.ErrShortWrite
	}
	return plainSize, nil
}

// ---- Container rs-strong 读取 ----

// gatherStrongSlots 读取 96 槽并逐槽验证 tag。
// 返回各槽载荷视图（同一缓冲的连续切片）、坏槽列表与 shardSize。
func (c *Container) gatherStrongSlots() (shards [][]byte, bad []int, shardSize int64, err error) {
	shardSize = layout.StrongShardSize(c.Man.PlainSize)
	slotSize := shardSize + int64(layout.TagSize)
	raw := make([]byte, int64(layout.StrongSlots)*slotSize)
	if _, err = c.src.ReadAt(raw, 0); err != nil && err != io.EOF {
		return nil, nil, 0, err
	}
	shards = make([][]byte, layout.StrongSlots)
	for i := 0; i < layout.StrongSlots; i++ {
		base := int64(i) * slotSize
		shards[i] = raw[base : base+shardSize]
		if !crypto.VerifyTag(shards[i], raw[base+shardSize:base+slotSize]) {
			bad = append(bad, i)
		}
	}
	return shards, bad, shardSize, nil
}

// reconstructStrong RS(32,64) 重建坏槽（容 ≤MStrong=64 槽坏；>64 数学上不可重建）。
// 成功返回全覆盖视图（原缓冲 + 重建槽），失败返回 (nil,false)。
func (c *Container) reconstructStrong(shards [][]byte, bad []int) ([][]byte, bool) {
	if len(bad) == 0 || len(bad) > layout.MStrong {
		return nil, false
	}
	views := make([][]byte, layout.StrongSlots)
	copy(views, shards)
	for _, i := range bad {
		views[i] = nil
	}
	if err := c.codecs.Strong().Reconstruct(views); err != nil {
		return nil, false
	}
	for _, i := range bad {
		if len(views[i]) != len(shards[0]) {
			return nil, false
		}
	}
	return views, true
}

// decodeStrongArea 拼前 32 个数据 shard 为 RS 数据区 → 解析 32B 块头 →
// GCM 终审（AAD = 块头）。数据内容与 manifest 不一致（块头 magic/index/PlainLen）
// 或 GCM 认证失败均按 ErrChunkUnrecoverable 处理（tag 全对也可能内容损坏——
// RS 只保证数学一致，信任锚是 GCM tag）。
func (c *Container) decodeStrongArea(shards [][]byte, shardSize int64) ([]byte, error) {
	dataArea := make([]byte, shardSize*layout.KStrong)
	for i := 0; i < layout.KStrong; i++ {
		if len(shards[i]) != int(shardSize) {
			return nil, &ChunkError{Index: 0, Err: errors.ErrChunkUnrecoverable}
		}
		copy(dataArea[int64(i)*shardSize:], shards[i])
	}
	hdr, err := format.ParseChunkHeader(dataArea[:layout.HeaderSize])
	if err != nil || hdr.Index != 0 || int64(hdr.PlainLen) != c.Man.PlainSize {
		return nil, &ChunkError{Index: 0, Err: errors.ErrChunkUnrecoverable}
	}
	need := hdr.PlainLen + layout.TagSize
	if int64(layout.HeaderSize+need) > int64(len(dataArea)) {
		return nil, &ChunkError{Index: 0, Err: errors.ErrChunkUnrecoverable}
	}
	plain, err := c.aead.Open(nil, hdr.Nonce, dataArea[layout.HeaderSize:layout.HeaderSize+need], dataArea[:layout.HeaderSize])
	if err != nil {
		return nil, &ChunkError{Index: 0, Err: fmt.Errorf("%w (gcm auth)", errors.ErrChunkUnrecoverable)}
	}
	return plain, nil
}

// LoadStrong rs-strong 完整读路径：96 槽逐槽 tag 验 → RS(32,64) 重建坏槽
//（容 ≤64 槽坏，>64 报 ErrChunkUnrecoverable——66.7% 容错边界）→ 拼数据区 → GCM 终审。
func (c *Container) LoadStrong() ([]byte, error) {
	shards, bad, shardSize, err := c.gatherStrongSlots()
	if err != nil {
		return nil, err
	}
	if len(bad) > 0 {
		fixed, ok := c.reconstructStrong(shards, bad)
		if !ok {
			return nil, &ChunkError{Index: 0, Err: errors.ErrChunkUnrecoverable}
		}
		shards = fixed
	}
	return c.decodeStrongArea(shards, shardSize)
}
