// Package engine 是 secvault 的编排引擎：读取侧容器（打开/收集/两级修复/GCM 终审）
// 与写入侧流水线（切块/并行编码/有序落盘/后台 parity）。
// 依赖 codec/format/crypto/layout，被顶层 API 门面调用。
package engine

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"

	"secvault/internal/codec"
	"secvault/internal/crypto"
	"secvault/internal/errors"
	"secvault/internal/format"
	"secvault/internal/layout"
)

// Container 是已打开容器的只读引擎：持有源、密钥、manifest 与编码器缓存。
// LoadChunk 提供 gather → 块内修复 → 文件级重建 → GCM 终审的完整读路径；
// Gather/Repair/Rebuild/Decode 细粒度方法供 scrub 编排使用。并发安全。
type Container struct {
	src      io.ReaderAt
	Man      format.Manifest
	spec     layout.Spec
	aead     crypto.AEAD
	ManAEAD  crypto.AEAD
	codecs   *codec.Cache
	Groups   int64
	KLast    int64
	FileSize int64
}

// Open 打开容器：定位并解密 manifest、校验尺寸一致性、装配引擎。
func Open(src io.ReaderAt, masterKey []byte) (*Container, error) {
	size, err := resolveSize(src)
	if err != nil {
		return nil, err
	}
	tailN := int64(65536)
	if size < tailN {
		tailN = size
	}
	if tailN < int64(format.TrailerFixed+4+16) {
		return nil, errors.ErrNoManifest
	}
	tail := make([]byte, tailN)
	if _, err := src.ReadAt(tail, size-tailN); err != nil && err != io.EOF {
		return nil, err
	}
	tr, err := format.ParseTrailer(tail)
	if err != nil {
		return nil, err
	}
	manAEAD, err := crypto.NewGCM(crypto.DeriveKey(masterKey, tr.FileID, "secvault/manifest/v1"))
	if err != nil {
		return nil, err
	}
	mb, err := manAEAD.Open(nil, tr.Nonce, tr.Payload, nil)
	if err != nil {
		return nil, errors.ErrManifestAuth
	}
	var man format.Manifest
	if err := json.Unmarshal(mb, &man); err != nil {
		return nil, fmt.Errorf("secvault: manifest json: %w", err)
	}
	trailerLen := int64(format.TrailerFixed + len(tr.Payload) + 4)
	if err := man.Validate(size, trailerLen); err != nil {
		return nil, err
	}
	aead, err := crypto.NewGCM(crypto.DeriveKey(masterKey, tr.FileID, "secvault/chunk/v1"))
	if err != nil {
		return nil, err
	}
	codecs, err := codec.NewCache()
	if err != nil {
		return nil, err
	}
	return &Container{
		src:      src,
		Man:      man,
		spec:     man.ResolveSpec(),
		aead:     aead,
		ManAEAD:  manAEAD,
		codecs:   codecs,
		Groups:   layout.GroupCount(man.ChunkCount),
		KLast:    layout.LastGroupChunks(man.ChunkCount),
		FileSize: size,
	}, nil
}

// ChunkError 携带出错块序号（内部用，顶层再导出包装）。
type ChunkError struct {
	Index int64
	Err   error
}

func (e *ChunkError) Error() string { return fmt.Sprintf("secvault: chunk %d: %v", e.Index, e.Err) }
func (e *ChunkError) Unwrap() error { return e.Err }

func resolveSize(src io.ReaderAt) (int64, error) {
	switch s := src.(type) {
	case interface{ Stat() (fs.FileInfo, error) }:
		fi, err := s.Stat()
		if err != nil {
			return 0, fmt.Errorf("secvault: stat: %w", err)
		}
		return fi.Size(), nil
	case interface{ Size() int64 }:
		return s.Size(), nil
	default:
		return 0, errors.New("secvault: source must implement Stat() or Size()")
	}
}

// DataChunks 组 g 的数据块数。
func (c *Container) DataChunks(g int64) int64 {
	return layout.DataChunksInGroup(g, c.Man.ChunkCount)
}

// GatherBlob 读取整块并逐槽验证 tag。payloads/tags 是同一缓冲的视图。
func (c *Container) GatherBlob(index int64) (payloads, tags [][]byte, bad []int, err error) {
	buf := make([]byte, layout.BlobDiskSize)
	if _, err = c.src.ReadAt(buf, c.spec.DataBlobOffset(index)); err != nil && err != io.EOF {
		return nil, nil, nil, err
	}
	payloads = make([][]byte, layout.ShardsPerBlob)
	tags = make([][]byte, layout.ShardsPerBlob)
	for i := 0; i < layout.ShardsPerBlob; i++ {
		off := i * layout.SlotSize
		payloads[i] = buf[off : off+layout.ShardSize]
		tags[i] = buf[off+layout.ShardSize : off+layout.SlotSize]
		if !crypto.VerifyTag(payloads[i], tags[i]) {
			bad = append(bad, i)
		}
	}
	return payloads, tags, bad, nil
}

// RepairIntra 块内 RS 修复（≤128 个 erasure，数学上精确重建）。
// 成功返回全覆盖 payloads；失败返回原视图与 false。
func (c *Container) RepairIntra(payloads [][]byte, bad []int) ([][]byte, bool) {
	if len(bad) == 0 || len(bad) > layout.ParityShards {
		return payloads, false
	}
	views := make([][]byte, layout.ShardsPerBlob)
	copy(views, payloads)
	for _, i := range bad {
		views[i] = nil
	}
	if err := c.codecs.Intra().Reconstruct(views); err != nil {
		return payloads, false
	}
	for _, i := range bad {
		if len(views[i]) != layout.ShardSize {
			return payloads, false
		}
		payloads[i] = views[i]
	}
	return payloads, true
}

// RebuildMissing 组级文件级重建：一次扫窗（32 列窗口）同时重建组内全部缺失 blob。
// 输入列逐槽验证 tag，坏列按 erasure 处理；erasure 总数（含缺失 blob）≤64 可容。
// 返回 组内位置 → 384 个 4KB 载荷。
func (c *Container) RebuildMissing(g int64, missing []int64) (map[int64][][]byte, bool) {
	kData := int(c.DataChunks(g))
	m := int(c.spec.GroupParity(g, c.Man.ChunkCount)) // v2 恒 64
	mset := make(map[int]bool, len(missing))
	for _, pos := range missing {
		if pos < 0 || pos >= int64(kData) {
			return nil, false
		}
		mset[int(pos)] = true
	}
	if len(mset) == 0 || len(mset) > m {
		return nil, false
	}
	rs, err := c.codecs.File(kData, m)
	if err != nil {
		return nil, false
	}

	const win = 32
	bufs := make(map[int][]byte, len(mset))

	for j0 := 0; j0 < layout.ShardsPerBlob; j0 += win {
		wc := win
		if j0+win > layout.ShardsPerBlob {
			wc = layout.ShardsPerBlob - j0
		}
		shards := make([][]byte, kData+m)
		erasures := 0

		for i := 0; i < kData; i++ {
			if mset[i] {
				shards[i] = nil
				erasures++
				continue
			}
			p, ok, _ := readWindow(c.src, c.spec.DataBlobOffset(g*layout.FileGroupChunks+int64(i))+int64(j0)*layout.SlotSize, wc)
			if !ok {
				shards[i] = nil
				erasures++
				continue
			}
			shards[i] = p
		}
		for p := 0; p < m; p++ {
			pb, ok, _ := readWindow(c.src, c.spec.ParityBlobOffset(g, c.DataChunks(g), int64(p))+int64(j0)*layout.SlotSize, wc)
			if !ok {
				shards[kData+p] = nil
				erasures++
				continue
			}
			shards[kData+p] = pb
		}
		if erasures > m {
			return nil, false
		}
		if err := rs.Reconstruct(shards); err != nil {
			return nil, false
		}
		for pos := range mset {
			if len(shards[pos]) != wc*layout.ShardSize {
				return nil, false
			}
			bufs[pos] = append(bufs[pos], shards[pos]...)
		}
	}

	out := make(map[int64][][]byte, len(mset))
	for pos := range mset {
		blob := bufs[pos]
		if len(blob) != layout.ShardsPerBlob*layout.ShardSize {
			return nil, false
		}
		payloads := make([][]byte, layout.ShardsPerBlob)
		for i := 0; i < layout.ShardsPerBlob; i++ {
			payloads[i] = blob[i*layout.ShardSize : (i+1)*layout.ShardSize]
		}
		out[int64(pos)] = payloads
	}
	return out, true
}

// RebuildBlobFileLevel 单块文件级重建（读路径灾难恢复）。
func (c *Container) RebuildBlobFileLevel(index int64) ([][]byte, bool) {
	m, ok := c.RebuildMissing(index/layout.FileGroupChunks, []int64{index % layout.FileGroupChunks})
	if !ok {
		return nil, false
	}
	return m[index%layout.FileGroupChunks], true
}

// DecodeChunk 从 384 个载荷中解析块头并 GCM 终审，返回明文。
func (c *Container) DecodeChunk(index int64, payloads [][]byte) ([]byte, error) {
	flat := make([]byte, 0, layout.BlobPlainSize)
	for i := 0; i < layout.DataShards; i++ {
		if len(payloads[i]) != layout.ShardSize {
			return nil, fmt.Errorf("shard %d missing after recovery", i)
		}
		flat = append(flat, payloads[i]...)
	}
	hdr, err := format.ParseChunkHeader(flat[:layout.HeaderSize])
	if err != nil {
		return nil, err
	}
	if hdr.Index != index {
		return nil, fmt.Errorf("header index %d != %d", hdr.Index, index)
	}
	if int64(binary.BigEndian.Uint64(hdr.Nonce[4:])) != index {
		return nil, errors.New("nonce/index mismatch")
	}
	if hdr.PlainLen < 1 || hdr.PlainLen > layout.ChunkPlainSize {
		return nil, fmt.Errorf("bad plainLen %d", hdr.PlainLen)
	}
	need := hdr.PlainLen + 16
	if layout.HeaderSize+need > layout.BlobPlainSize {
		return nil, errors.New("plainLen overflow")
	}
	plain, err := c.aead.Open(nil, hdr.Nonce, flat[layout.HeaderSize:layout.HeaderSize+need], flat[:layout.HeaderSize])
	if err != nil {
		return nil, fmt.Errorf("%w (gcm auth)", errors.ErrChunkUnrecoverable)
	}
	return plain, nil
}

// LoadChunk 完整读路径：收集 → 块内修复 → 文件级重建 → 解码。
func (c *Container) LoadChunk(index int64) ([]byte, error) {
	if index < 0 || index >= c.Man.ChunkCount {
		return nil, fmt.Errorf("secvault: chunk index %d out of range [0,%d)", index, c.Man.ChunkCount)
	}
	payloads, _, bad, err := c.GatherBlob(index)
	if err != nil {
		return nil, err
	}
	if len(bad) > 0 {
		if fixed, ok := c.RepairIntra(payloads, bad); ok {
			payloads = fixed
		} else if rebuilt, ok2 := c.RebuildBlobFileLevel(index); ok2 {
			payloads = rebuilt
		} else {
			return nil, &ChunkError{Index: index, Err: errors.ErrChunkUnrecoverable}
		}
	}
	plain, derr := c.DecodeChunk(index, payloads)
	if derr != nil {
		return nil, &ChunkError{Index: index, Err: derr}
	}
	return plain, nil
}
