package secvault

import (
	"fmt"
	"io"
	"secvault/internal/layout"
	"sync"

	"secvault/internal/engine"
)

// Reader 打开并读取 secvault 容器，实现 io.ReaderAt 语义（明文视图）。
// 读取路径自带透明修复：块内 ≤128 个坏 shard 内存重建；超出时整块走
// 文件级 RS 重建。并发安全（内部有缓存与 codec 锁）。
type Reader struct {
	c *engine.Container

	cacheMu    sync.RWMutex
	cacheIdx   int64
	cachePlain []byte
}

// Open 打开容器并校验 manifest。
func Open(src io.ReaderAt, masterKey []byte) (*Reader, error) {
	c, err := engine.Open(src, masterKey)
	if err != nil {
		return nil, err
	}
	return &Reader{c: c, cacheIdx: -1}, nil
}

// PlainSize 明文总长。
func (r *Reader) PlainSize() int64 { return r.c.Man.PlainSize }

// ChunkCount 块数。
func (r *Reader) ChunkCount() int64 { return r.c.Man.ChunkCount }

// ReadChunkAt 返回整块明文。buf 可为 nil；容量足够时复用之。
// 返回值由调用方持有，与内部缓存无别名。
func (r *Reader) ReadChunkAt(index int64, buf []byte) ([]byte, error) {
	if index < 0 || index >= r.c.Man.ChunkCount {
		return nil, fmt.Errorf("secvault: chunk index %d out of range [0,%d)", index, r.c.Man.ChunkCount)
	}
	if plain, ok := r.cached(index); ok {
		return cloneInto(buf, plain), nil
	}
	plain, err := r.c.LoadChunk(index)
	if err != nil {
		return nil, wrapChunkErr(err)
	}
	r.cacheMu.Lock()
	r.cacheIdx, r.cachePlain = index, plain
	r.cacheMu.Unlock()
	return cloneInto(buf, plain), nil
}

// ReadAt 实现 io.ReaderAt（明文视图）。
func (r *Reader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, ErrNegativeOffset
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= r.c.Man.PlainSize {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) {
		abs := off + int64(n)
		if abs >= r.c.Man.PlainSize {
			break
		}
		idx := abs / layout.ChunkPlainSize
		inOff := abs % layout.ChunkPlainSize
		plain, ok := r.cached(idx)
		if !ok {
			var err error
			if plain, err = r.c.LoadChunk(idx); err != nil {
				return n, wrapChunkErr(err)
			}
			r.cacheMu.Lock()
			r.cacheIdx, r.cachePlain = idx, plain
			r.cacheMu.Unlock()
		}
		n += copy(p[n:], plain[inOff:])
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (r *Reader) cached(idx int64) ([]byte, bool) {
	r.cacheMu.RLock()
	defer r.cacheMu.RUnlock()
	if r.cacheIdx == idx && r.cachePlain != nil {
		return r.cachePlain, true
	}
	return nil, false
}

// wrapChunkErr 把 engine.ChunkError 换成公共 ChunkError（保持 errors.Is 语义）。
func wrapChunkErr(err error) error {
	if ce, ok := err.(*engine.ChunkError); ok {
		return &ChunkError{Index: ce.Index, Err: ce.Err}
	}
	return err
}

func cloneInto(buf, src []byte) []byte {
	if cap(buf) < len(src) {
		buf = make([]byte, len(src))
	}
	return append(buf[:0], src...)
}
