package secvault_test

import (
	"errors"
	"secvault"
	"secvault/internal/testutil"

	"io"
	"io/fs"
	"os"
	"sync"
	"testing"

	"secvault/internal/layout"
)

// osOpenRW 打开可读写文件（Scrub 需要 ReadAt+WriteAt）。
type rwHandle struct {
	mu sync.Mutex
	f  *os.File
}

func osOpenRW(path string) (*rwHandle, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	return &rwHandle{f: f}, nil
}

func (h *rwHandle) ReadAt(p []byte, off int64) (int, error) {
	return h.f.ReadAt(p, off)
}

func (h *rwHandle) WriteAt(p []byte, off int64) (int, error) {
	return h.f.WriteAt(p, off)
}

func (h *rwHandle) Stat() (fs.FileInfo, error) { return h.f.Stat() }
func (h *rwHandle) Close() error               { return h.f.Close() }

func assertDiskPlain(t *testing.T, path string, plain []byte) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := secvault.Open(f, testutil.TestKey)
	if err != nil {
		t.Fatalf("Open after scrub: %v", err)
	}
	got := make([]byte, len(plain))
	if _, err := r.ReadAt(got, 0); err != nil && err != io.EOF {
		t.Fatalf("read after scrub: %v", err)
	}
	if !testutil.BytesEqual(got, plain) {
		t.Fatal("plaintext mismatch after scrub")
	}
}

// TestScrubPristine 干净文件 scrub：零修复、零写入（digest 不变）。
func TestScrubPristine(t *testing.T) {
	plain := testutil.MakePlain(3*layout.ChunkPlainSize+5, 21)
	mf := testutil.WriteVault(t, plain)
	before := testutil.Digest(mf.Bytes())
	rep, err := secvault.Scrub(mf, testutil.TestKey, secvault.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.ChunksTotal != 4 || rep.ChunksClean != 4 || rep.ShardsBad != 0 ||
		rep.ChunksRepaired != 0 || rep.ChunksRebuilt != 0 || len(rep.ChunksLost) != 0 {
		t.Fatalf("report: %+v", rep)
	}
	if after := testutil.Digest(mf.Bytes()); after != before {
		t.Fatal("pristine scrub modified the file")
	}
}

// TestVerifyReadOnly Verify 绝不修改文件。
func TestVerifyReadOnly(t *testing.T) {
	plain := testutil.MakePlain(3*layout.ChunkPlainSize, 23)
	mf := testutil.WriteVault(t, plain)
	for i := 0; i < 5; i++ {
		testutil.CorruptSlot(t, mf, 0, int64(i*7), i*13+1)
	}
	before := testutil.Digest(mf.Bytes())
	rep, err := secvault.Verify(mf, testutil.TestKey, secvault.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.ShardsBad != 5 || rep.ChunksRepaired != 1 || rep.ChunksClean != 2 {
		t.Fatalf("report: %+v", rep)
	}
	if after := testutil.Digest(mf.Bytes()); after != before {
		t.Fatal("Verify modified the file")
	}
}

// TestScrubShardRepair 块内修复：回写后二次 scrub 零修复，读取恒等。
func TestScrubShardRepair(t *testing.T) {
	plain := testutil.MakePlain(3*layout.ChunkPlainSize+99, 27)
	mf := testutil.WriteVault(t, plain)
	for i := 0; i < 100; i++ {
		testutil.CorruptSlot(t, mf, 1, int64(i*3), i*31+5)
	}
	corrupted := testutil.Digest(mf.Bytes())

	rep, err := secvault.Scrub(mf, testutil.TestKey, secvault.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.ShardsRepaired != 100 || rep.ChunksRepaired != 1 || rep.ChunksClean != 3 || len(rep.ChunksLost) != 0 {
		t.Fatalf("report: %+v", rep)
	}
	if after := testutil.Digest(mf.Bytes()); after == corrupted {
		t.Fatal("scrub did not write repairs")
	}
	testutil.AssertPlain(t, mf2Reader(t, mf), plain)

	rep2, err := secvault.Scrub(mf, testutil.TestKey, secvault.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep2.ShardsBad != 0 || rep2.ChunksClean != 4 {
		t.Fatalf("second scrub: %+v", rep2)
	}
}

// mf2Reader 从已写入的 memFile 重新打开只读 secvault.Reader。
func mf2Reader(t *testing.T, mf *testutil.MemFile) *secvault.Reader {
	t.Helper()
	r, err := secvault.Open(mf, testutil.TestKey)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestScrubFileLevelRebuild 整块清零 → scrub 走文件级重建并回写。
func TestScrubFileLevelRebuild(t *testing.T) {
	plain := testutil.MakePlain(2*layout.ChunkPlainSize+40, 33)
	mf := testutil.WriteVault(t, plain)
	testutil.ZeroBlob(t, mf, 0)
	rep, err := secvault.Scrub(mf, testutil.TestKey, secvault.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.ChunksRebuilt != 1 || rep.ChunksClean != 2 || len(rep.ChunksLost) != 0 {
		t.Fatalf("report: %+v", rep)
	}
	testutil.AssertPlain(t, mf2Reader(t, mf), plain)
}

// TestScrubParityRebuild 文件级 parity 损坏的检测与修复。
func TestScrubParityRebuild(t *testing.T) {
	plain := testutil.MakePlain(3*layout.ChunkPlainSize+40, 35)
	mf := testutil.WriteVault(t, plain)
	_ = 0
	// 破坏组 0 parity blob 0 的 8 个槽
	for i := 0; i < 8; i++ {
		testutil.FlipByte(t, mf, layout.ParityBlobOffset(0, 0)+int64(i)*layout.SlotSize+int64(100+i))
	}

	// 不开 RebuildParity：不检测、不改 parity，数据读取不受影响
	rep1, err := secvault.Scrub(mf, testutil.TestKey, secvault.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep1.ParitySlotsBad != 0 || rep1.ParityShardsFixed != 0 {
		t.Fatalf("report1: %+v", rep1)
	}
	// 开启 RebuildParity：检出并修复
	rep2, err := secvault.Scrub(mf, testutil.TestKey, secvault.Options{RebuildParity: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep2.ParitySlotsBad != 8 || rep2.ParityShardsFixed != 8 {
		t.Fatalf("report2: %+v", rep2)
	}
	// 再跑一遍应零检出
	rep3, err := secvault.Scrub(mf, testutil.TestKey, secvault.Options{RebuildParity: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep3.ParitySlotsBad != 0 || rep3.ParityShardsFixed != 0 {
		t.Fatalf("report3: %+v", rep3)
	}
	testutil.AssertPlain(t, mf2Reader(t, mf), plain)
}

// TestScrubLost 大范围损坏（-short 跳过）：65 块整块清零 → 精确判死。
func TestScrubLost(t *testing.T) {
	if testing.Short() {
		t.Skip("large test")
	}
	const chunks = 130
	plain := testutil.MakePlain(chunks*layout.ChunkPlainSize, 91)
	p := testutil.DiskVault(t, plain)
	f, err := osOpenRW(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for c := int64(0); c < 65; c++ {
		testutil.ZeroBlob(t, f, c)
	}
	rep, err := secvault.Scrub(f, testutil.TestKey, secvault.Options{RebuildParity: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.ChunksLost) != 65 || rep.ChunksRebuilt != 0 {
		t.Fatalf("report: %+v", rep)
	}
	for i, idx := range rep.ChunksLost {
		if idx != int64(i) {
			t.Fatalf("lost[%d]=%d", i, idx)
		}
	}
	if rep.ChunksClean != chunks-65 {
		t.Fatalf("clean=%d", rep.ChunksClean)
	}
	if rep.ChunksClean+rep.ChunksRepaired+rep.ChunksRebuilt+int64(len(rep.ChunksLost)) != rep.ChunksTotal {
		t.Fatal("accounting broken")
	}
	// 含丢失块的组 parity 不应被重算
	if rep.ParitySlotsBad != 0 || rep.ParityShardsFixed != 0 {
		t.Fatalf("parity touched despite lost chunks: %+v", rep)
	}
	// 直接读：丢失块报错
	r, err := secvault.Open(f, testutil.TestKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, idx := range []int64{0, 32, 64} {
		if _, err := r.ReadChunkAt(idx, nil); !errors.Is(err, secvault.ErrChunkUnrecoverable) {
			t.Fatalf("chunk %d: got %v", idx, err)
		}
	}
}

// TestScrubTruncated 截断文件 scrub → 干净报错。
func TestScrubTruncated(t *testing.T) {
	plain := testutil.MakePlain(layout.ChunkPlainSize+1, 41)
	mf := testutil.WriteVault(t, plain)
	full := mf.Bytes()
	m2 := testutil.NewMemFile()
	m2.Write(full[:len(full)-30])
	if _, err := secvault.Scrub(m2, testutil.TestKey, secvault.Options{}); !errors.Is(err, secvault.ErrNoManifest) {
		t.Fatalf("got %v", err)
	}
	if _, err := secvault.Verify(m2, testutil.TestKey, secvault.Options{}); !errors.Is(err, secvault.ErrNoManifest) {
		t.Fatalf("verify: got %v", err)
	}
}

// TestReportAccounting 账目守恒（修复路径混合场景）。
func TestReportAccounting(t *testing.T) {
	plain := testutil.MakePlain(3*layout.ChunkPlainSize, 43)
	mf := testutil.WriteVault(t, plain)
	// chunk0: 50 槽（块内）；chunk1: 整块清零（文件级）；chunk2: 不动
	for i := 0; i < 50; i++ {
		testutil.CorruptSlot(t, mf, 0, int64(i*5), i*37+3)
	}
	testutil.ZeroBlob(t, mf, 1)
	rep, err := secvault.Scrub(mf, testutil.TestKey, secvault.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.ChunksRepaired != 1 || rep.ShardsRepaired != 50 || rep.ChunksRebuilt != 1 || rep.ChunksClean != 1 || len(rep.ChunksLost) != 0 {
		t.Fatalf("report: %+v", rep)
	}
	if rep.ChunksClean+rep.ChunksRepaired+rep.ChunksRebuilt+int64(len(rep.ChunksLost)) != rep.ChunksTotal {
		t.Fatal("accounting broken")
	}
	testutil.AssertPlain(t, mf2Reader(t, mf), plain)
}
