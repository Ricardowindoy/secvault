// Package format 实现 secvault 磁盘格式的字节级编解码：
// 32B 块头、manifest JSON 校验、尾部 trailer 帧定位。
// 只做编解码，不做解密与修复语义（那是 engine 的职责）。
package format

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"

	"secvault/internal/errors"
	"secvault/internal/layout"
)

// FormatVersion 当前格式版本。
const FormatVersion = 2

const (
	magicTrailer = "SVLT"
	magicChunk   = "SVC1"

	FileIDSize   = 16
	TrailerFixed = 40 // trailer 除密文与 CRC 外的固定头
)

var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

// ChunkHeader 32B 块头（明文元数据，受 shard tag + GCM AAD 双重保护）。
type ChunkHeader struct {
	Index    int64
	PlainLen int
	Nonce    []byte // 12B
}

// Marshal 编码 32B 块头。
func (h *ChunkHeader) Marshal() []byte {
	b := make([]byte, layout.HeaderSize)
	copy(b, magicChunk)
	binary.BigEndian.PutUint64(b[4:], uint64(h.Index))
	binary.BigEndian.PutUint64(b[12:], uint64(h.PlainLen))
	copy(b[20:], h.Nonce)
	return b
}

// ParseChunkHeader 解码并校验 magic。
func ParseChunkHeader(b []byte) (*ChunkHeader, error) {
	if len(b) < layout.HeaderSize || string(b[:4]) != magicChunk {
		return nil, errors.New("chunk header magic mismatch")
	}
	return &ChunkHeader{
		Index:    int64(binary.BigEndian.Uint64(b[4:])),
		PlainLen: int(binary.BigEndian.Uint64(b[12:])),
		Nonce:    append([]byte(nil), b[20:32]...),
	}, nil
}

// Manifest 尾部加密清单。K2 记录名义组大小（128），实际末组 kData 由 ChunkCount 推导。
type Manifest struct {
	Version    int   `json:"v"`
	K          int   `json:"k"`
	M          int   `json:"m"`
	K2         int   `json:"k2"`
	M2         int   `json:"m2"`
	ShardSize  int   `json:"ss"`
	ChunkPlain int   `json:"cp"`
	ChunkCount int64 `json:"cc"`
	PlainSize  int64 `json:"ps"`
}

// ResolveSpec 从 manifest 解析布局参数。当前恒为 v2（v3 落地后按 m.Version 分支）。
func (m *Manifest) ResolveSpec() layout.Spec {
	return layout.SpecV2()
}

// Validate 校验 manifest 参数与文件尺寸一致性（尺寸不符即截断/追加）；
// 尺寸期望由 ResolveSpec 解析出的布局参数计算（组数、末组块数等随版本集中到 layout.Spec）。
func (m *Manifest) Validate(size, trailerLen int64) error {
	if m.Version != FormatVersion ||
		m.K != layout.DataShards || m.M != layout.ParityShards ||
		m.K2 != layout.FileGroupChunks || m.M2 != layout.FileParityShards ||
		m.ShardSize != layout.ShardSize || m.ChunkPlain != layout.ChunkPlainSize {
		return errors.ErrUnsupportedFormat
	}
	if m.ChunkCount < 0 || m.PlainSize < 0 {
		return errors.ErrUnsupportedFormat
	}
	if m.ChunkCount == 0 && m.PlainSize != 0 {
		return errors.ErrUnsupportedFormat
	}
	if m.ChunkCount > 0 {
		minSize := (m.ChunkCount-1)*layout.ChunkPlainSize + 1
		if m.PlainSize < minSize || m.PlainSize > m.ChunkCount*layout.ChunkPlainSize {
			return errors.ErrUnsupportedFormat
		}
	}
	if expect := m.ResolveSpec().TotalBlobCount(m.ChunkCount)*layout.BlobDiskSize + trailerLen; expect != size {
		return errors.ErrNoManifest // 尺寸对不上：截断或追加
	}
	return nil
}

// Trailer 尾部帧（40B 固定头 + manifest 密文 + CRC32C）。
type Trailer struct {
	Version int
	FileID  []byte // 16B HKDF 盐（明文，非机密）
	Nonce   []byte // 12B manifest GCM nonce
	Payload []byte // manifest 密文+GCM tag
}

// BuildTrailer 序列化 trailer（含 CRC32C 帧校验）。
func BuildTrailer(t *Trailer) []byte {
	out := make([]byte, 0, TrailerFixed+len(t.Payload)+4)
	out = append(out, magicTrailer...)
	out = append(out, byte(t.Version), 0, 0, 0)
	out = append(out, t.FileID...)
	out = append(out, t.Nonce...)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(t.Payload)))
	out = append(out, l[:]...)
	out = append(out, t.Payload...)
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], crc32.Checksum(out, crc32cTable))
	return append(out, c[:]...)
}

// ParseTrailer 在文件尾部缓冲中定位 trailer（必须以文件 EOF 结尾）。
// 找不到返回 errors.ErrNoManifest。
func ParseTrailer(tail []byte) (*Trailer, error) {
	for i := len(tail) - 4; i >= 0; i-- {
		if string(tail[i:i+4]) != magicTrailer {
			continue
		}
		if i+TrailerFixed > len(tail) {
			continue
		}
		l := int(binary.BigEndian.Uint32(tail[i+36 : i+40]))
		end := i + TrailerFixed + l + 4
		if end != len(tail) || l < 16 {
			continue
		}
		body := tail[i : end-4]
		if crc32.Checksum(body, crc32cTable) != binary.BigEndian.Uint32(tail[end-4:]) {
			continue
		}
		if tail[i+4] != FormatVersion {
			return nil, fmt.Errorf("secvault: format version %d unsupported", tail[i+4])
		}
		return &Trailer{
			Version: int(tail[i+4]),
			FileID:  append([]byte(nil), tail[i+8:i+24]...),
			Nonce:   append([]byte(nil), tail[i+24:i+36]...),
			Payload: append([]byte(nil), tail[i+40:end-4]...),
		}, nil
	}
	return nil, errors.ErrNoManifest
}
