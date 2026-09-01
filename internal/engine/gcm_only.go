package engine

// gcm-only scheme 读写后端（v3 批次1，FORMAT-v3.md §4）：
// 整个文件一个 GCM 单元，无 RS、无分块、无 shard tag。
// 与流式 Pipeline 不兼容（必须缓冲全部明文才能 Seal），故顶层 Writer 按 scheme
// 持有 SmallFileSink 后端分派，rs-dual 路径保持不变。

import (
	"bytes"
	"fmt"
	"io"

	"secvault/internal/crypto"
	ierrors "secvault/internal/errors"
	"secvault/internal/format"
	"secvault/internal/layout"
)

// SmallFileSink 小文件 scheme（gcm-only / rs-strong）的写入后端接口：
// 单 blob 缓冲语义——先全收下，Close 时一次编码落盘。gcm/strong 各一实现。
type SmallFileSink interface {
	// Write 缓冲明文（单 blob：先全收下，Drain 时一次编码）。
	Write(p []byte) (int, error)
	// Drain 编码 + 落盘正文，返回明文总长。
	// scheme 由实现固定，调用方已知；trailer 由顶层 Writer 在 Drain 之后追加
	//（偏移按 scheme 的 layout 尺寸公式计算）。
	Drain() (plainSize int64, err error)
}

// ---- gcm-only 写入后端 ----

// gcmOnlySink 缓冲全部明文，Drain 时一次性 GCM 认证加密并写到正文区偏移 0。
type gcmOnlySink struct {
	dst  io.ReadWriteSeeker
	aead crypto.AEAD // HKDF(master, fileID, "secvault/gcm/v1")
	buf  []byte      // 明文缓冲（增长式）
}

// NewGCMOnlySink 构造 gcm-only 写入后端（顶层 Writer 经 SmallFileSink 接口持有）。
func NewGCMOnlySink(dst io.ReadWriteSeeker, aead crypto.AEAD) SmallFileSink {
	return &gcmOnlySink{dst: dst, aead: aead}
}

func (g *gcmOnlySink) Write(p []byte) (int, error) {
	g.buf = append(g.buf, p...)
	return len(p), nil
}

// Drain：nonce 随机 → Seal(buf, nonce, header) → 写 [magic+nonce][密文+tag] 到偏移 0。
// AAD = 16B 头（magic+nonce），头随密文一起受 GCM 认证保护。
func (g *gcmOnlySink) Drain() (int64, error) {
	nonce, err := crypto.RandomBytes(layout.NonceSize)
	if err != nil {
		return 0, err
	}
	header := make([]byte, layout.GCMHeaderSize) // [4B SVGO][12B nonce]
	copy(header, layout.MagicGCMOnly())
	copy(header[len(layout.MagicGCMOnly()):], nonce)
	ct := g.aead.Seal(nil, nonce, g.buf, header)
	out := append(header, ct...)
	if _, err := g.dst.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}
	if n, err := g.dst.Write(out); err != nil {
		return 0, err
	} else if n != len(out) {
		return 0, io.ErrShortWrite
	}
	return int64(len(g.buf)), nil
}

// ---- Container gcm-only 读取 ----

// LoadGCMOnly 读取并解密 gcm-only 正文：ReadAt 整个载荷 → GCM.Open（AAD=16B 头）。
// GCM.Open 失败 → ErrGCMOnlyCorrupted（检测到损坏/篡改，交调用方重拉——本类别无修复路径）。
func (c *Container) LoadGCMOnly() ([]byte, error) {
	payloadSize := layout.GCMOnlyPayloadSize(c.Man.PlainSize)
	buf := make([]byte, payloadSize)
	if _, err := c.src.ReadAt(buf, 0); err != nil && err != io.EOF {
		return nil, err
	}
	header := buf[:layout.GCMHeaderSize]
	if !bytes.Equal(header[:4], layout.MagicGCMOnly()) {
		// magic 不符：正文区已损坏/被替换（manifest 完好故判定正文损坏）
		return nil, fmt.Errorf("secvault: gcm-only magic mismatch: %w", ierrors.ErrGCMOnlyCorrupted)
	}
	nonce := header[4:]
	ct := buf[layout.GCMHeaderSize : layout.GCMHeaderSize+c.Man.PlainSize+layout.TagSize]
	plain, err := c.aead.Open(nil, nonce, ct, header)
	if err != nil {
		return nil, ierrors.ErrGCMOnlyCorrupted
	}
	return plain, nil
}

// LoadAll 小文件 scheme 的统一读取入口：一次性返回全部明文。
// 按 scheme 分派：gcm-only → LoadGCMOnly；rs-strong → LoadStrong；
// rs-dual 无此语义（分块随机访问走 LoadChunk）。
func (c *Container) LoadAll() ([]byte, error) {
	switch c.Scheme() {
	case format.SchemeGCMOnly:
		return c.LoadGCMOnly()
	case format.SchemeRSStrong:
		return c.LoadStrong()
	default:
		return nil, ierrors.New("secvault: LoadAll on rs-dual (use LoadChunk)")
	}
}
