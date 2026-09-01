package secvault_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math/rand"
	"os"
	"secvault"
	"secvault/internal/format"
	"secvault/internal/layout"
	"secvault/internal/testutil"
	"sync"
	"testing"
)

// ---- 往返与尺寸边界 ----

var crc32cTableRef = crc32.MakeTable(crc32.Castagnoli)

func TestRoundTripSizes(t *testing.T) {
	sizes := []int{
		0, 1, 2, 15, 16, 17, 4095, 4096, 4097, 65535, 65536,
		layout.ChunkPlainSize - 1, layout.ChunkPlainSize, layout.ChunkPlainSize + 1,
		2 * layout.ChunkPlainSize, 2*layout.ChunkPlainSize + 12345,
		3*layout.ChunkPlainSize + 777, 5*layout.ChunkPlainSize + 999,
	}
	for i, n := range sizes {
		t.Run(fmt.Sprintf("n%d", n), func(t *testing.T) {
			plain := testutil.MakePlain(n, int64(100+i))
			mf := testutil.WriteVault(t, plain)
			r, err := secvault.Open(mf, testutil.TestKey)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if r.PlainSize() != int64(n) {
				t.Fatalf("PlainSize=%d want %d", r.PlainSize(), n)
			}
			if r.ChunkCount() != int64((n+layout.ChunkPlainSize-1)/layout.ChunkPlainSize) {
				t.Fatalf("ChunkCount=%d", r.ChunkCount())
			}
			testutil.AssertPlain(t, r, plain)
			// 逐块 ReadChunkAt 交叉验证
			for idx := int64(0); idx*layout.ChunkPlainSize < int64(n); idx++ {
				end := min(int64(n), (idx+1)*layout.ChunkPlainSize)
				got, err := r.ReadChunkAt(idx, nil)
				if err != nil {
					t.Fatalf("ReadChunkAt(%d): %v", idx, err)
				}
				if !bytes.Equal(got, plain[idx*layout.ChunkPlainSize:end]) {
					t.Fatalf("chunk %d mismatch", idx)
				}
			}
		})
	}
}

func TestBytePatterns(t *testing.T) {
	// 全零 / 全 FF / 周期模式：确认填充与解码无别名
	n := 3*layout.ChunkPlainSize + 4096
	zeros := make([]byte, n)
	ff := bytes.Repeat([]byte{0xFF}, n)
	period := make([]byte, n)
	for i := range period {
		period[i] = byte(i % 251)
	}
	for i, plain := range [][]byte{zeros, ff, period} {
		mf := testutil.WriteVault(t, plain)
		r, err := secvault.Open(mf, testutil.TestKey)
		if err != nil {
			t.Fatal(err)
		}
		if got := testutil.ReadAll(t, r, int64(n)); !bytes.Equal(got, plain) {
			t.Fatalf("pattern %d mismatch", i)
		}
	}
}

func TestOddWriteSizes(t *testing.T) {
	plain := testutil.MakePlain(2*layout.ChunkPlainSize+33333, 42)
	mf := testutil.NewMemFile()
	w, err := secvault.NewWriter(mf, testutil.TestKey)
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(7))
	for off := 0; off < len(plain); {
		n := rng.Intn(8191) + 1
		if off+n > len(plain) {
			n = len(plain) - off
		}
		if _, err := w.Write(plain[off : off+n]); err != nil {
			t.Fatal(err)
		}
		off += n
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := secvault.Open(mf, testutil.TestKey)
	if err != nil {
		t.Fatal(err)
	}
	testutil.AssertPlain(t, r, plain)
}

// ---- Writer 错误路径 ----

func TestWriterKeyValidation(t *testing.T) {
	for _, n := range []int{0, 1, 16, 31, 33, 64} {
		if _, err := secvault.NewWriter(testutil.NewMemFile(), make([]byte, n)); !errors.Is(err, secvault.ErrInvalidKey) {
			t.Fatalf("keylen %d: got %v", n, err)
		}
	}
	if _, err := secvault.NewWriter(nil, testutil.TestKey); err == nil {
		t.Fatal("nil dst accepted")
	}
}

func TestWriterClosedErrors(t *testing.T) {
	mf := testutil.NewMemFile()
	w, _ := secvault.NewWriter(mf, testutil.TestKey)
	if err := w.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := w.Close(); !errors.Is(err, secvault.ErrClosed) {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := w.Write([]byte("x")); !errors.Is(err, secvault.ErrClosed) {
		t.Fatalf("Write after Close: %v", err)
	}
}

// ---- Open 错误路径 ----

func TestOpenGarbage(t *testing.T) {
	mf := testutil.NewMemFile()
	mf.Write(testutil.MakePlain(1<<20, 3))
	if _, err := secvault.Open(mf, testutil.TestKey); !errors.Is(err, secvault.ErrNoManifest) {
		t.Fatalf("garbage: got %v", err)
	}
}

func TestOpenTruncatedAndAppended(t *testing.T) {
	plain := testutil.MakePlain(3*layout.ChunkPlainSize+4242, 9)
	mf := testutil.WriteVault(t, plain)
	full := mf.Bytes()

	// 基线：完整文件可打开
	r, err := secvault.Open(mf, testutil.TestKey)
	if err != nil {
		t.Fatalf("baseline Open: %v", err)
	}
	testutil.AssertPlain(t, r, plain)

	cuts := []int64{0, 1, 100, layout.BlobDiskSize - 1, layout.BlobDiskSize, 2 * layout.BlobDiskSize,
		int64(len(full)) - 1000, int64(len(full)) - 60, int64(len(full)) - 45,
		int64(len(full)) - 41, int64(len(full)) - 40, int64(len(full)) - 5}
	for _, cut := range cuts {
		if cut >= int64(len(full)) {
			continue
		}
		m := testutil.NewMemFile()
		m.Write(full[:cut])
		if _, err := secvault.Open(m, testutil.TestKey); !errors.Is(err, secvault.ErrNoManifest) {
			t.Fatalf("truncated @%d: got %v", cut, err)
		}
	}
	// 追加垃圾
	m := testutil.NewMemFile()
	m.Write(full)
	m.Write([]byte("garbage!"))
	if _, err := secvault.Open(m, testutil.TestKey); !errors.Is(err, secvault.ErrNoManifest) {
		t.Fatalf("appended: got %v", err)
	}
	// 盲改 manifest 密文：CRC（帧定位用，非密钥）先拦截 → secvault.ErrNoManifest
	m2 := testutil.NewMemFile()
	m2.Write(full)
	testutil.FlipByte(t, m2, int64(len(full))-45)
	if _, err := secvault.Open(m2, testutil.TestKey); !errors.Is(err, secvault.ErrNoManifest) {
		t.Fatalf("manifest blind tamper: got %v", err)
	}
	// 知情篡改（重算 CRC）：CRC 无密钥可重算 → 必须由 GCM 认证拦截
	m3 := testutil.NewMemFile()
	m3.Write(full)
	tailN := int64(65536)
	if tailN > int64(len(full)) {
		tailN = int64(len(full))
	}
	tr, err := format.ParseTrailer(full[len(full)-int(tailN):])
	if err != nil {
		t.Fatal(err)
	}
	trailerStart := int64(len(full)) - (int64(format.TrailerFixed) + int64(len(tr.Payload)) + 4)
	testutil.FlipByte(t, m3, trailerStart+format.TrailerFixed+10) // manifest 密文内部
	body := m3.Bytes()[trailerStart : int64(len(full))-4]
	var crc [4]byte
	binary.BigEndian.PutUint32(crc[:], crc32.Checksum(body, crc32cTableRef))
	m3.WriteAt(crc[:], int64(len(full))-4)
	if _, err := secvault.Open(m3, testutil.TestKey); !errors.Is(err, secvault.ErrManifestAuth) {
		t.Fatalf("manifest informed tamper: got %v", err)
	}
}

func TestOpenWrongKey(t *testing.T) {
	plain := testutil.MakePlain(layout.ChunkPlainSize+17, 11)
	mf := testutil.WriteVault(t, plain)
	if _, err := secvault.Open(mf, testutil.WrongKey); !errors.Is(err, secvault.ErrManifestAuth) {
		t.Fatalf("wrong key: got %v", err)
	}
}

// ---- ReaderAt 语义 ----

func TestReaderAtSemantics(t *testing.T) {
	plain := testutil.MakePlain(2*layout.ChunkPlainSize+777, 13)
	r, err := secvault.Open(testutil.WriteVault(t, plain), testutil.TestKey)
	if err != nil {
		t.Fatal(err)
	}
	size := int64(len(plain))

	// 精确到 EOF
	buf := make([]byte, 100)
	if n, err := r.ReadAt(buf, size-10); n != 10 || err != io.EOF {
		t.Fatalf("tail read: n=%d err=%v", n, err)
	}
	if !bytes.Equal(buf[:10], plain[size-10:]) {
		t.Fatal("tail content mismatch")
	}
	// 越界
	if n, err := r.ReadAt(buf, size); n != 0 || err != io.EOF {
		t.Fatalf("past-end: n=%d err=%v", n, err)
	}
	// 负偏移
	if _, err := r.ReadAt(buf, -1); !errors.Is(err, secvault.ErrNegativeOffset) {
		t.Fatalf("negative: %v", err)
	}
	// 零长读
	if n, err := r.ReadAt(nil, 0); n != 0 || err != nil {
		t.Fatalf("zero-len: n=%d err=%v", n, err)
	}
	// 跨块边界
	off := layout.ChunkPlainSize - 100
	got := make([]byte, 200)
	if _, err := r.ReadAt(got, int64(off)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain[off:off+200]) {
		t.Fatal("cross-chunk mismatch")
	}
	// 大缓冲覆盖整个文件
	if n, err := r.ReadAt(make([]byte, size+1000), 0); n != int(size) || err != io.EOF {
		t.Fatalf("full read: n=%d err=%v", n, err)
	}
}

// ---- 并发读 ----

func TestConcurrentReads(t *testing.T) {
	plain := testutil.MakePlain(2*layout.ChunkPlainSize+1234, 55)
	r, err := secvault.Open(testutil.WriteVault(t, plain), testutil.TestKey)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errCh := make(chan error, 64)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(g) + 500))
			buf := make([]byte, 8192)
			for i := 0; i < 200; i++ {
				off := rng.Int63n(int64(len(plain)))
				length := rng.Intn(8191) + 1
				end := min(off+int64(length), int64(len(plain)))
				want := plain[off:end]
				n, err := r.ReadAt(buf[:len(want)], off)
				if err != nil && err != io.EOF {
					errCh <- fmt.Errorf("g%d off%d: %w", g, off, err)
					return
				}
				if n != len(want) || !bytes.Equal(buf[:n], want) {
					errCh <- fmt.Errorf("g%d off%d: content mismatch", g, off)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

// ---- 布局数学（v2：组内 parity 在前）----

func TestLayoutMath(t *testing.T) {
	for _, cc := range []int64{0, 1, 2, 127, 128, 129, 130, 255, 256, 257, 384, 385, 1000} {
		if cc == 0 {
			if layout.SpecV2().TotalBlobCount(0) != 0 || layout.GroupCount(0) != 0 {
				t.Fatal("empty file layout")
			}
			continue
		}
		G := layout.GroupCount(cc)
		if want := (G-1)*layout.BlobsPerFullGroup + layout.LastGroupChunks(cc) + layout.FileParityShards; layout.SpecV2().TotalBlobCount(cc) != want {
			t.Fatalf("cc=%d totalBlob=%d want %d", cc, layout.SpecV2().TotalBlobCount(cc), want)
		}
		// 组 0 parity 从文件 0 开始
		if got := layout.SpecV2().ParityBlobOffset(0, layout.DataChunksInGroup(0, cc), 0); got != 0 {
			t.Fatalf("cc=%d group0 parity0=%d", cc, got)
		}
		// 首个数据块紧跟组 0 parity 区
		if got, want := layout.SpecV2().DataBlobOffset(0), int64(layout.FileParityShards)*layout.BlobDiskSize; got != want {
			t.Fatalf("cc=%d blob0=%d want %d", cc, got, want)
		}
		// 末组 parity 末尾 == 末组首个数据块（组内连续）
		if got, want := layout.SpecV2().ParityBlobOffset(G-1, layout.DataChunksInGroup(G-1, cc), layout.FileParityShards-1)+layout.BlobDiskSize, layout.SpecV2().DataBlobOffset((G-1)*layout.FileGroupChunks); got != want {
			t.Fatalf("cc=%d last parity end %d want %d", cc, got, want)
		}
		// 文件数据区末尾 = 总 blob 数末尾
		if got, want := layout.SpecV2().DataBlobOffset(cc-1)+layout.BlobDiskSize, layout.SpecV2().TotalBlobCount(cc)*layout.BlobDiskSize; got != want {
			t.Fatalf("cc=%d end %d want %d", cc, got, want)
		}
		if cc > layout.FileGroupChunks {
			if got, want := layout.SpecV2().ParityBlobOffset(1, layout.DataChunksInGroup(1, cc), 0), layout.BlobsPerFullGroup*layout.BlobDiskSize; got != want {
				t.Fatalf("cc=%d group1 parity0=%d want %d", cc, got, want)
			}
		}
		// blobOffset 严格单调
		prev := int64(-1)
		for i := int64(0); i < cc; i++ {
			if layout.SpecV2().DataBlobOffset(i) <= prev {
				t.Fatalf("cc=%d blobOffset not monotonic at %d", cc, i)
			}
			prev = layout.SpecV2().DataBlobOffset(i)
		}
	}
}

// ---- 大文件多组（-short 跳过）----

func TestLargeMultiGroup(t *testing.T) {
	if testing.Short() {
		t.Skip("large test")
	}
	plain := testutil.MakePlain(130*layout.ChunkPlainSize, 77)
	p := testutil.DiskVault(t, plain)
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := secvault.Open(f, testutil.TestKey)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if r.ChunkCount() != 130 || r.PlainSize() != int64(len(plain)) {
		t.Fatalf("manifest: cc=%d ps=%d", r.ChunkCount(), r.PlainSize())
	}
	for _, idx := range []int64{0, 1, 126, 127, 128, 129} {
		got, err := r.ReadChunkAt(idx, nil)
		if err != nil {
			t.Fatalf("chunk %d: %v", idx, err)
		}
		start := idx * layout.ChunkPlainSize
		end := min(int64(len(plain)), start+layout.ChunkPlainSize)
		if !bytes.Equal(got, plain[start:end]) {
			t.Fatalf("chunk %d mismatch", idx)
		}
	}
	// 全量读
	got := testutil.ReadAll(t, r, int64(len(plain)))
	if !bytes.Equal(got, plain) {
		t.Fatal("full mismatch")
	}
	// 干净 scrub
	rep, err := secvault.Scrub(f, testutil.TestKey, secvault.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.ChunksTotal != 130 || rep.ChunksClean != 130 || rep.ShardsBad != 0 || len(rep.ChunksLost) != 0 {
		t.Fatalf("pristine scrub report: %+v", rep)
	}
}
