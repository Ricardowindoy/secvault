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

// FormatVersionV3 v3 格式版本（v3：data-first 组布局 + 自适应文件级 parity）。
// FormatVersion 保持 2 作为缺省写出版本（v3 由 WithFileParity 显式启用）。
const FormatVersionV3 = 3

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
// v3 起 Manifest 增加 scheme 维度：字段语义按 scheme 分化（见 ResolveScheme/Validate），
// gcm-only/rs-strong 无"块/组"概念，rs-dual 专有字段（k/m/k2/m2/ss/cp/cc）保持零值。
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
	// Scheme v3 scheme（"gcm" | "rs-strong" | "rs-dual"）。
	// 空值=rs-dual（v2/旧 v3 文件无此字段，向后兼容）。
	Scheme string `json:"sc,omitempty"`
	// KStrong/MStrong rs-strong 冗余记录（=32/64，固定可推导，记录以支持前向校验）。
	KStrong int `json:"ks,omitempty"`
	MStrong int `json:"ms,omitempty"`
}

// Scheme 容器 scheme（三类别，FORMAT-v3.md §3）。
type Scheme string

const (
	SchemeRSDual   Scheme = "rs-dual"
	SchemeGCMOnly  Scheme = "gcm"
	SchemeRSStrong Scheme = "rs-strong"
)

// ResolveScheme 从 manifest 解析 scheme：空/缺失 → rs-dual（v2 与旧 v3 兼容）。
func (m *Manifest) ResolveScheme() Scheme {
	if m.Scheme == "" {
		return SchemeRSDual
	}
	return Scheme(m.Scheme)
}

// ResolveSpec 从 manifest 解析布局参数：v2 → SpecV2（parity-first、恒 64 parity）；
// v3 → SpecV3(m.Version>=3 时 M2 字段即 M2Cap)。
// 注意：仅 rs-dual 有组/块布局；gcm-only/rs-strong 的尺寸不经 Spec，
// 直接用 layout.GCMOnlySize / layout.StrongSize 计算。
func (m *Manifest) ResolveSpec() layout.Spec {
	if m.Version >= FormatVersionV3 {
		return layout.SpecV3(int64(m.M2))
	}
	return layout.SpecV2()
}

// Validate 校验 manifest 参数与文件尺寸一致性（尺寸不符即截断/追加）。
// 按 scheme 分派：rs-dual（含 v2 兼容）走组/块布局校验；
// gcm-only/rs-strong 走各自的文件级单 blob 布局公式。
func (m *Manifest) Validate(size, trailerLen int64) error {
	switch m.ResolveScheme() {
	case SchemeGCMOnly:
		return m.validateGCMOnly(size, trailerLen)
	case SchemeRSStrong:
		return m.validateRSStrong(size, trailerLen)
	case SchemeRSDual:
		return m.validateRSDual(size, trailerLen)
	default:
		return errors.ErrUnsupportedFormat
	}
}

// validateRSDual rs-dual（含 v2）尺寸校验：期望由 ResolveSpec 解析出的布局参数计算
// （组数、末组块数等随版本集中到 layout.Spec）。
func (m *Manifest) validateRSDual(size, trailerLen int64) error {
	if m.Version != FormatVersion && m.Version != FormatVersionV3 ||
		m.K != layout.DataShards || m.M != layout.ParityShards ||
		m.K2 != layout.FileGroupChunks ||
		m.ShardSize != layout.ShardSize || m.ChunkPlain != layout.ChunkPlainSize {
		return errors.ErrUnsupportedFormat
	}
	// M2 版本感知：v2 恒为 FileParityShards(64)；v3 为文件级 parity 上限，可取 [1, 64]。
	if m.M2 != layout.FileParityShards {
		if m.Version != FormatVersionV3 || m.M2 < 1 || m.M2 > layout.FileParityShards {
			return errors.ErrUnsupportedFormat
		}
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

// validateGCMOnly gcm-only 尺寸校验：size == 16 + plainSize + 16 + trailerLen。
// 无 RS/无分块——rs-dual 专有字段必须为零。
func (m *Manifest) validateGCMOnly(size, trailerLen int64) error {
	if m.Version != FormatVersionV3 {
		return errors.ErrUnsupportedFormat
	}
	if m.K != 0 || m.M != 0 || m.K2 != 0 || m.M2 != 0 ||
		m.ShardSize != 0 || m.ChunkPlain != 0 || m.ChunkCount != 0 ||
		m.KStrong != 0 || m.MStrong != 0 {
		return errors.ErrUnsupportedFormat
	}
	if m.PlainSize < 0 {
		return errors.ErrUnsupportedFormat
	}
	if expect := layout.GCMOnlySize(m.PlainSize, trailerLen); expect != size {
		return errors.ErrNoManifest // 尺寸对不上：截断或追加
	}
	return nil
}

// validateRSStrong rs-strong 尺寸校验：size == 96×(shardSize+16) + trailerLen，
// shardSize = ceil((32+plainSize+16)/32)。k/m 复用为 rs-strong 的 RS(32,64) 维度
// （无"块"概念，同一对值的不同语义），与 ks/ms 冗余记录交叉校验。
func (m *Manifest) validateRSStrong(size, trailerLen int64) error {
	if m.Version != FormatVersionV3 {
		return errors.ErrUnsupportedFormat
	}
	if m.K != layout.KStrong || m.M != layout.MStrong ||
		m.KStrong != layout.KStrong || m.MStrong != layout.MStrong {
		return errors.ErrUnsupportedFormat
	}
	if m.K2 != 0 || m.M2 != 0 || m.ChunkPlain != 0 || m.ChunkCount != 0 {
		return errors.ErrUnsupportedFormat
	}
	if m.PlainSize < 0 {
		return errors.ErrUnsupportedFormat
	}
	if m.ShardSize != int(layout.StrongShardSize(m.PlainSize)) {
		return errors.ErrUnsupportedFormat
	}
	if expect := layout.StrongSize(m.PlainSize, trailerLen); expect != size {
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
		v := int(tail[i+4])
		if v != FormatVersion && v != FormatVersionV3 {
			return nil, fmt.Errorf("secvault: format version %d unsupported", v)
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
