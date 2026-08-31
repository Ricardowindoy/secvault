// Package testutil 提供 secvault 的测试工具：内存文件、确定性数据、容器构造、损坏注入。
// 仅测试代码引用（单元测试与 bench），不进入生产路径。
package testutil

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"secvault"
	"secvault/internal/layout"
)

// ---- 固定测试密钥 ----

var TestKey = func() []byte {
	k := make([]byte, layout.MasterKeySize)
	for i := range k {
		k[i] = byte(i*11 + 3)
	}
	return k
}()

var WrongKey = func() []byte {
	k := make([]byte, layout.MasterKeySize)
	for i := range k {
		k[i] = byte(i*5 + 99)
	}
	return k
}()

// ---- memFile：全接口内存文件 ----

type MemFile struct {
	mu   sync.RWMutex
	data []byte
	pos  int64
}

func NewMemFile() *MemFile { return &MemFile{} }

// resize 零填充扩到 end（append 语义，底层容量复用，amortized O(1)）。
func (m *MemFile) resize(end int64) {
	for int64(len(m.data)) < end {
		need := end - int64(len(m.data))
		step := int64(len(m.data))
		if step == 0 {
			step = 4096
		}
		if step > need {
			step = need
		}
		m.data = append(m.data, make([]byte, step)...)
	}
}

func (m *MemFile) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	end := m.pos + int64(len(p))
	if end > int64(len(m.data)) {
		if m.pos == int64(len(m.data)) { // 顺序追加快路径
			m.data = append(m.data, p...)
			m.pos = end
			return len(p), nil
		}
		m.resize(end)
	}
	copy(m.data[m.pos:], p)
	m.pos = end
	return len(p), nil
}

func (m *MemFile) Read(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pos >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[m.pos:])
	m.pos += int64(n)
	return n, nil
}

func (m *MemFile) Seek(offset int64, whence int) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var target int64
	switch whence {
	case io.SeekStart:
		target = offset
	case io.SeekCurrent:
		target = m.pos + offset
	case io.SeekEnd:
		target = int64(len(m.data)) + offset
	default:
		return 0, fmt.Errorf("secvault test: bad whence %d", whence)
	}
	if target < 0 {
		return 0, errors.New("secvault test: negative seek")
	}
	m.pos = target
	return target, nil
}

func (m *MemFile) ReadAt(p []byte, off int64) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if off < 0 {
		return 0, errors.New("secvault test: negative ReadAt")
	}
	if off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (m *MemFile) WriteAt(p []byte, off int64) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if off < 0 {
		return 0, errors.New("secvault test: negative WriteAt")
	}
	end := off + int64(len(p))
	if end > int64(len(m.data)) {
		if off == int64(len(m.data)) {
			m.data = append(m.data, p...)
			return len(p), nil
		}
		m.resize(end)
	}
	copy(m.data[off:], p)
	return len(p), nil
}

func (m *MemFile) Truncate(n int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if n <= int64(len(m.data)) {
		m.data = m.data[:n] // 保留底层容量，append 复用
		return
	}
	m.resize(n)
}

func (m *MemFile) Size() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return int64(len(m.data))
}

func (m *MemFile) Bytes() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]byte, len(m.data))
	copy(out, m.data)
	return out
}

func (m *MemFile) Stat() (fs.FileInfo, error) { return memInfo{size: m.Size()}, nil }

type memInfo struct{ size int64 }

func (mi memInfo) Name() string       { return "mem.svdat" }
func (mi memInfo) Size() int64        { return mi.size }
func (mi memInfo) Mode() fs.FileMode  { return 0o644 }
func (mi memInfo) ModTime() time.Time { return time.Time{} }
func (mi memInfo) IsDir() bool        { return false }
func (mi memInfo) Sys() any           { return nil }

// ---- 数据与容器构造 ----

// makePlain 确定性伪随机明文。
func MakePlain(n int, seed int64) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

func WriteVault(t *testing.T, plain []byte) *MemFile {
	t.Helper()
	mf := NewMemFile()
	w, err := secvault.NewWriter(mf, TestKey)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return mf
}

// diskVault 在包目录下（磁盘持久，避开 /tmp tmpfs 内存压力）生成容器文件。
func DiskVault(t *testing.T, plain []byte) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", "secvault-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	p := filepath.Join(dir, "v.svdat")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w, err := secvault.NewWriter(f, TestKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

func ReadAll(t *testing.T, r *secvault.Reader, size int64) []byte {
	t.Helper()
	out := make([]byte, size)
	if _, err := r.ReadAt(out, 0); err != nil && err != io.EOF {
		t.Fatalf("ReadAt: %v", err)
	}
	return out
}

func AssertPlain(t *testing.T, r *secvault.Reader, plain []byte) {
	t.Helper()
	got := ReadAll(t, r, int64(len(plain)))
	if !BytesEqual(got, plain) {
		t.Fatalf("plaintext mismatch (size %d)", len(plain))
	}
}

func BytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func Digest(b []byte) string {
	s := sha256.Sum256(b)
	return fmt.Sprintf("%x", s[:8])
}

// ---- 损坏注入 ----

type RwFile interface {
	io.ReaderAt
	io.WriterAt
}

// flipByte 在绝对偏移处翻转一个字节。
func FlipByte(t *testing.T, f RwFile, off int64) {
	t.Helper()
	var b [1]byte
	if _, err := f.ReadAt(b[:], off); err != nil {
		t.Fatalf("flipByte read @%d: %v", off, err)
	}
	b[0] ^= 0xFF
	if _, err := f.WriteAt(b[:], off); err != nil {
		t.Fatalf("flipByte write @%d: %v", off, err)
	}
}

// corruptSlot 翻转 (chunk, slot) 槽内 payload 的 inner 偏移字节（inner ∈ [0,4096)）。
func CorruptSlot(t *testing.T, f RwFile, chunk, slot int64, inner int) {
	t.Helper()
	if inner < 0 || inner >= layout.ShardSize {
		t.Fatalf("inner %d out of payload range", inner)
	}
	FlipByte(t, f, layout.BlobOffset(chunk)+slot*layout.SlotSize+int64(inner))
}

// corruptTag 翻转 (chunk, slot) 槽的 tag 区字节。
func CorruptTag(t *testing.T, f RwFile, chunk, slot int64, inner int) {
	t.Helper()
	if inner < 0 || inner >= layout.TagSize {
		t.Fatalf("inner %d out of tag range", inner)
	}
	FlipByte(t, f, layout.BlobOffset(chunk)+slot*layout.SlotSize+layout.ShardSize+int64(inner))
}

// zeroBlob 整块清零（模拟整块彻底损坏）。
func ZeroBlob(t *testing.T, f RwFile, chunk int64) {
	buf := make([]byte, layout.BlobDiskSize)
	if _, err := f.WriteAt(buf, layout.BlobOffset(chunk)); err != nil {
		t.Fatal(err)
	}
}
