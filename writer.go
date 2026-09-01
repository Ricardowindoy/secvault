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
func WithFileParity(m int) WriterOption {
	return func(o *writerOpts) {
		if m >= 1 && m <= layout.FileParityShards {
			o.m2cap = m
			o.formatV3 = true
		}
	}
}

// Writer 流式写入加密容器（缺省 v2 无屏障流水线；WithFileParity 显式启用 v3
// 自适应 parity，详见 FORMAT.md / FORMAT-v3.md 写入语义）。
// Write 允许异步：返回时块可能尚未落盘，错误延后至后续 Write/Close 冒泡；
// Close 必须调用（排空流水线 + 写 trailer）。非并发安全（单 goroutine 调用）。
// dst 需要可读可写可寻址（*os.File 满足）；必须从空文件/偏移 0 开始。
type Writer struct {
	dst      io.ReadWriteSeeker
	pipeline *engine.Pipeline
	manAEAD  crypto.AEAD
	fileID   []byte
	spec     layout.Spec
	version  int
	m2cap    int
	closed   bool
}

// NewWriter 创建写入器。masterKey 必须恰好 32 字节。
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
	pfx, err := crypto.RandomBytes(4)
	if err != nil {
		return nil, err
	}
	aead, err := crypto.NewGCM(crypto.DeriveKey(masterKey, fileID, "secvault/chunk/v1"))
	if err != nil {
		return nil, err
	}
	manAEAD, err := crypto.NewGCM(crypto.DeriveKey(masterKey, fileID, "secvault/manifest/v1"))
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
		m2cap:    o.m2cap,
	}, nil
}

// Write 流式写入明文（内部切块，返回 ≠ 已落盘）。
func (w *Writer) Write(p []byte) (int, error) {
	if w.closed {
		return 0, ErrClosed
	}
	return w.pipeline.Write(p)
}

// Close 冲刷部分块、排空流水线与 parity 累加器、补齐末组并写 trailer。
func (w *Writer) Close() error {
	if w.closed {
		return ErrClosed
	}
	w.closed = true
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
	// trailer 紧随全部数据/parity blob 之后；组跨度/末组 parity 随 spec（v2/v3）自适应。
	off := w.spec.TotalBlobCount(chunkCount) * layout.BlobDiskSize
	if _, err := w.dst.Seek(off, io.SeekStart); err != nil {
		return err
	}
	if _, err := w.dst.Write(tr); err != nil {
		return err
	}
	return nil
}
