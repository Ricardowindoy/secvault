package secvault

import (
	"fmt"
	"io"
	"secvault/internal/layout"
	"sync"

	"secvault/internal/engine"
	"secvault/internal/format"
)

// Reader 打开并读取 secvault 容器，实现 io.ReaderAt 语义（明文视图）。
// 读取路径按 scheme 分派：
//   - rs-dual：块级随机访问 + 透明修复（块内 ≤128 个坏 shard 内存重建；超出时
//     整块走文件级 RS 重建），单块缓存。
//   - gcm-only / rs-strong：文件级单 blob——首次访问 LoadAll() 缓冲全部明文
//     （allPlain），ReadChunkAt(0) 返回全部、ReadAt 切片返回。
//
// 并发安全（内部有缓存与 codec 锁）。
type Reader struct {
	c *engine.Container

	cacheMu    sync.RWMutex
	cacheIdx   int64
	cachePlain []byte
	allLoaded  bool
	allPlain   []byte // gcm-only/rs-strong 全量明文缓冲（首次访问 LoadAll）
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
// rs-dual：块级（index ∈ [0, ChunkCount)）；gcm-only/rs-strong：整文件为一个单元，
// 仅 index==0 合法（返回全部明文），其他 index 越界。
func (r *Reader) ReadChunkAt(index int64, buf []byte) ([]byte, error) {
	if r.c.Scheme() != format.SchemeRSDual {
		if index != 0 {
			return nil, fmt.Errorf("secvault: chunk index %d out of range [0,1) (single-blob scheme)", index)
		}
		plain, err := r.loadAllPlain()
		if err != nil {
			return nil, err
		}
		return cloneInto(buf, plain), nil
	}
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
	if r.c.Scheme() != format.SchemeRSDual {
		return r.readAtSmall(p, off)
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

// loadAllPlain 返回 gcm-only/rs-strong 容器的全量明文（首次访问 LoadAll 并缓冲，
// 并发安全）。返回值与内部缓冲共享，调用方不得修改。
func (r *Reader) loadAllPlain() ([]byte, error) {
	r.cacheMu.RLock()
	if r.allLoaded {
		p := r.allPlain
		r.cacheMu.RUnlock()
		return p, nil
	}
	r.cacheMu.RUnlock()
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	if r.allLoaded {
		return r.allPlain, nil
	}
	plain, err := r.c.LoadAll()
	if err != nil {
		return nil, err
	}
	r.allPlain, r.allLoaded = plain, true
	return plain, nil
}

// readAtSmall 单 blob scheme 的 ReadAt：从全量缓冲切片返回（io.ReaderAt 边界语义
// 与 rs-dual 路径一致：越界 → io.EOF，部分读 → n, io.EOF）。
func (r *Reader) readAtSmall(p []byte, off int64) (int, error) {
	plain, err := r.loadAllPlain()
	if err != nil {
		return 0, err
	}
	if off >= int64(len(plain)) {
		return 0, io.EOF
	}
	n := copy(p, plain[off:])
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
