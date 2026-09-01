package secvault

import (
	"encoding/json"
	"fmt"
	"io"

	"secvault/internal/codec"
	"secvault/internal/crypto"
	"secvault/internal/engine"
	ierrors "secvault/internal/errors"
	"secvault/internal/format"
	"secvault/internal/layout"
)

// WriterOption 调整流水线参数。
type WriterOption func(*writerOpts)

type writerOpts struct {
	workers  int
	inflight int
	m2cap    int
	formatV3 bool
	scheme   string // 容器 scheme：""/"rs-dual" | "gcm"（批次2 "rs-strong"）；后写覆盖前写
}

// WithWorkers 编码 worker 数（默认 4）。
func WithWorkers(n int) WriterOption {
	return func(o *writerOpts) {
		if n >= 1 && n <= 16 {
			o.workers = n
		}
	}
}

// WithInflight 流水线积压上限（块数，默认 16；每 in-flight 块约 2.6MB 内存）。
func WithInflight(n int) WriterOption {
	return func(o *writerOpts) {
		if n >= 4 && n <= 256 {
			o.inflight = n
		}
	}
}

// WithFileParity 设置文件级 parity 上限（1..FileParityShards），并启用 v3 格式
// （data-first 组布局 + 自适应末组 parity：末组 parity = min(m2cap, kData)）。
// 缺省写 v2 格式（M2 恒 64，末组也 64）。m2cap=64 时 v3 满组与 v2 等价，
// 仅末组按 1:1 上限收紧——这是 v3.0 自适应 parity 的默认形态。
// 与 WithRePull 互斥：同时设置时以最后一个 option 为准（后写覆盖前写）。
func WithFileParity(m int) WriterOption {
	return func(o *writerOpts) {
		if m >= 1 && m <= layout.FileParityShards {
			o.m2cap = m
			o.formatV3 = true
			o.scheme = string(format.SchemeRSDual)
		}
	}
}

// WithRePull 声明内容可从源站重拉（缩略图/元数据/字幕）→ gcm-only scheme
// （~1×空间，GCM.Open 失败即报损坏交调用方重拉，无 RS 修复路径）。
// 隐式启用 v3 格式。与 WithFileParity/WithStrongRS 互斥：同时设置时以最后一个
// option 为准（后写覆盖前写，不阻断）。
func WithRePull() WriterOption {
	return func(o *writerOpts) {
		o.scheme = string(format.SchemeGCMOnly)
		o.formatV3 = true
	}
}

// WithStrongRS 声明内容为不可重拉的小文件（<1MB）→ rs-strong scheme
//（固定 RS(32,64)、96 槽、变长 shardSize = ceil((32+ps+16)/32)，
// 66.7% 散落损坏容错，~3.15× 空间）。隐式启用 v3 格式。
// 与 WithRePull/WithFileParity 互斥：同时设置时以最后一个 option 为准
//（后写覆盖前写，不阻断）。
func WithStrongRS() WriterOption {
	return func(o *writerOpts) {
		o.scheme = string(format.SchemeRSStrong)
		o.formatV3 = true
	}
}

// Writer 流式写入加密容器。scheme 分派（sum-type，不引入多余抽象）：
//   - rs-dual（缺省，无 option=v2 / WithFileParity=v3）：无屏障流式流水线（Pipeline）。
//   - gcm-only（WithRePull）/ rs-strong（WithStrongRS）：单 blob 缓冲后一次性编码
//     （SmallFileSink 后端，gcm/strong 各一实现）。
//
// Write 的异步语义仅 rs-dual 成立（返回 ≠ 已落盘，错误延后冒泡）；gcm-only/rs-strong
// 同步缓冲。Close 必须调用（排空后端 + 写 trailer）。非并发安全（单 goroutine 调用）。
// dst 需要可读可写可寻址（*os.File 满足）；必须从空文件/偏移 0 开始。
type Writer struct {
	dst      io.ReadWriteSeeker
	manAEAD  crypto.AEAD
	fileID   []byte
	version  int
	scheme   string               // "rs-dual" | "gcm" | "rs-strong"
	m2cap    int                  // 仅 rs-dual 用
	spec     layout.Spec          // 仅 rs-dual 用
	pipeline *engine.Pipeline     // scheme=="rs-dual" 时非 nil
	sink     engine.SmallFileSink // scheme!="rs-dual" 时非 nil（gcm/strong 各一实现）
	closed   bool
}

// NewWriter 创建写入器。masterKey 必须恰好 32 字节。
// scheme 由 option 决定：缺省/WithFileParity → rs-dual（Pipeline）；
// WithRePull → gcm-only（后端 AEAD 派生用独立 HKDF info "secvault/gcm/v1"）；
// WithStrongRS → rs-strong（复用 chunk 域 "secvault/chunk/v1" 与 32B 块头）。
func NewWriter(dst io.ReadWriteSeeker, masterKey []byte, opts ...WriterOption) (*Writer, error) {
	if len(masterKey) != layout.MasterKeySize {
		return nil, ErrInvalidKey
	}
	if dst == nil {
		return nil, ierrors.New("secvault: nil destination")
	}
	o := writerOpts{workers: 4, inflight: 16, m2cap: layout.FileParityShards}
	for _, f := range opts {
		f(&o)
	}
	fileID, err := crypto.RandomBytes(format.FileIDSize)
	if err != nil {
		return nil, err
	}
	manAEAD, err := crypto.NewGCM(crypto.DeriveKey(masterKey, fileID, "secvault/manifest/v1"))
	if err != nil {
		return nil, err
	}
	if o.scheme == string(format.SchemeGCMOnly) {
		// gcm-only：无 RS、无分块——不需要 codec 缓存与流水线；
		// 数据 AEAD 用 gcm 独立 HKDF 域（区别于 chunk 的 "secvault/chunk/v1"）。
		aead, err := crypto.NewGCM(crypto.DeriveKey(masterKey, fileID, "secvault/gcm/v1"))
		if err != nil {
			return nil, err
		}
		return &Writer{
			dst:     dst,
			manAEAD: manAEAD,
			fileID:  fileID,
			version: format.FormatVersionV3,
			scheme:  string(format.SchemeGCMOnly),
			sink:    engine.NewGCMOnlySink(dst, aead),
		}, nil
	}
	if o.scheme == string(format.SchemeRSStrong) {
		// rs-strong：单 blob RS(32,64)——复用 chunk 密钥域与 32B 块头（SVC1），
		// codec 缓存提供 warmup 过的 RS(32,64) 编码器（变长 shardSize 对其透明）。
		aead, err := crypto.NewGCM(crypto.DeriveKey(masterKey, fileID, "secvault/chunk/v1"))
		if err != nil {
			return nil, err
		}
		codecs, err := codec.NewCache()
		if err != nil {
			return nil, err
		}
		return &Writer{
			dst:     dst,
			manAEAD: manAEAD,
			fileID:  fileID,
			version: format.FormatVersionV3,
			scheme:  string(format.SchemeRSStrong),
			sink:    engine.NewStrongSink(dst, aead, codecs),
		}, nil
	}
	// rs-dual（"" 缺省或显式 "rs-dual"）：v2 无屏障流水线 / v3 自适应 parity，路径不变。
	pfx, err := crypto.RandomBytes(4)
	if err != nil {
		return nil, err
	}
	aead, err := crypto.NewGCM(crypto.DeriveKey(masterKey, fileID, "secvault/chunk/v1"))
	if err != nil {
		return nil, err
	}
	codecs, err := codec.NewCache()
	if err != nil {
		return nil, err
	}
	var noncePfx [4]byte
	copy(noncePfx[:], pfx)
	version := format.FormatVersion
	spec := layout.SpecV2()
	if o.formatV3 {
		version = format.FormatVersionV3
		spec = layout.SpecV3(int64(o.m2cap))
	}
	return &Writer{
		dst:      dst,
		pipeline: engine.NewPipeline(dst, aead, codecs, noncePfx, o.workers, o.inflight, spec),
		manAEAD:  manAEAD,
		fileID:   fileID,
		spec:     spec,
		version:  version,
		scheme:   string(format.SchemeRSDual),
		m2cap:    o.m2cap,
	}, nil
}

// Write 流式写入明文（rs-dual：内部切块，返回 ≠ 已落盘；gcm-only/rs-strong：同步缓冲）。
func (w *Writer) Write(p []byte) (int, error) {
	if w.closed {
		return 0, ErrClosed
	}
	if w.pipeline != nil {
		return w.pipeline.Write(p)
	}
	return w.sink.Write(p)
}

// Close 冲刷并排空写入后端、写 trailer。按 scheme 分派：
// rs-dual 排空流水线与 parity 累加器；gcm-only 一次性 GCM 落盘；
// rs-strong 一次性 GCM+RS(32,64) 编码落盘。
// trailer 偏移按 scheme 的 layout 尺寸公式计算。
func (w *Writer) Close() error {
	if w.closed {
		return ErrClosed
	}
	w.closed = true
	if w.pipeline != nil {
		return w.closeRSDual()
	}
	return w.closeSmall()
}

// closeRSDual rs-dual 收尾：排空流水线 → manifest → trailer（TotalBlobCount 偏移）。
func (w *Writer) closeRSDual() error {
	chunkCount, plainSize, err := w.pipeline.Drain()
	if err != nil {
		return err
	}
	man := format.Manifest{
		Version:    w.version,
		K:          layout.DataShards,
		M:          layout.ParityShards,
		K2:         layout.FileGroupChunks,
		M2:         w.m2cap,
		ShardSize:  layout.ShardSize,
		ChunkPlain: layout.ChunkPlainSize,
		ChunkCount: chunkCount,
		PlainSize:  plainSize,
	}
	// trailer 紧随全部数据/parity blob 之后；组跨度/末组 parity 随 spec（v2/v3）自适应。
	off := w.spec.TotalBlobCount(chunkCount) * layout.BlobDiskSize
	return w.writeTrailer(man, off)
}

// closeSmall 小文件 scheme（gcm-only / rs-strong）收尾：sink.Drain 一次性编码落盘
// → manifest（scheme 字段 + plainSize，rs-strong 另记 RS 维度与变长 shardSize）
// → trailer（scheme 专属偏移）。
func (w *Writer) closeSmall() error {
	plainSize, err := w.sink.Drain()
	if err != nil {
		return err
	}
	var man format.Manifest
	var off int64
	switch format.Scheme(w.scheme) {
	case format.SchemeGCMOnly:
		man = format.Manifest{
			Version:   w.version,
			Scheme:    w.scheme,
			PlainSize: plainSize,
		}
		off = layout.GCMOnlyPayloadSize(plainSize) // = 16 + plainSize + 16
	case format.SchemeRSStrong:
		man = format.Manifest{
			Version: w.version,
			Scheme:  w.scheme,
			K:       layout.KStrong, // 复用 k/m 记录 rs-strong 的 RS(32,64) 维度
			M:       layout.MStrong,
			// ShardSize 变长（ceil((32+ps+16)/32)），Validate 依 PlainSize 交叉校验。
			ShardSize: int(layout.StrongShardSize(plainSize)),
			PlainSize: plainSize,
			KStrong:   layout.KStrong,
			MStrong:   layout.MStrong,
			// K2/M2/ChunkPlain/ChunkCount 保持零值（无块/组概念）。
		}
		off = layout.StrongPayloadSize(plainSize) // = 96 × (shardSize + 16)
	default:
		return ierrors.New("secvault: unknown writer scheme " + w.scheme)
	}
	return w.writeTrailer(man, off)
}

// writeTrailer 加密 manifest 并追加 trailer 到 off 偏移（trailer 帧结构 v2/v3 一致）。
func (w *Writer) writeTrailer(man format.Manifest, off int64) error {
	mb, err := json.Marshal(&man)
	if err != nil {
		return fmt.Errorf("secvault: manifest json: %w", err)
	}
	nonce, err := crypto.RandomBytes(layout.NonceSize)
	if err != nil {
		return err
	}
	tr := format.BuildTrailer(&format.Trailer{
		Version: w.version,
		FileID:  w.fileID,
		Nonce:   nonce,
		Payload: w.manAEAD.Seal(nil, nonce, mb, nil),
	})
	if _, err := w.dst.Seek(off, io.SeekStart); err != nil {
		return err
	}
	if _, err := w.dst.Write(tr); err != nil {
		return err
	}
	return nil
}
