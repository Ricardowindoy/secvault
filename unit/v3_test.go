package secvault_test

// v3 格式（自适应文件级 parity）单元测试。
//
// 覆盖：data-first 组布局 + 末组 parity = min(M2Cap, kLast) 的往返/尺寸一致性、
// 与 v2 的尺寸对比、manifest 元数据、损坏修复路径（块内 / 文件级重建）。
// 全部经 WithFileParity 显式启用 v3；不触碰现有 v2 默认路径测试。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"

	"secvault"
	"secvault/internal/crypto"
	"secvault/internal/format"
	"secvault/internal/layout"
	"secvault/internal/testutil"
)

// writeVaultOpt 用指定 Writer 选项写容器到临时文件并回卷到文件头
// （v3 测试专用；不改动 testutil.WriteVault 的 v2 语义）。
func writeVaultOpt(t *testing.T, plain []byte, opts ...secvault.WriterOption) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "vault-v3")
	if err != nil {
		t.Fatal(err)
	}
	w, err := secvault.NewWriter(f, testutil.TestKey, opts...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(w, bytes.NewReader(plain)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	return f
}

// trailerOf 读取文件尾部（末 64KB）并解析 trailer 帧。
func trailerOf(t *testing.T, f *os.File) *format.Trailer {
	t.Helper()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	tailN := int64(65536)
	if fi.Size() < tailN {
		tailN = fi.Size()
	}
	tail := make([]byte, tailN)
	if _, err := f.ReadAt(tail, fi.Size()-tailN); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	tr, err := format.ParseTrailer(tail)
	if err != nil {
		t.Fatalf("ParseTrailer: %v", err)
	}
	return tr
}

// assertV3FileSize 断言文件尺寸与 v3 布局数学严格一致：
// size == SpecV3(m2cap).TotalBlobCount(cc)*BlobDiskSize + trailerLen
// （trailerLen = TrailerFixed + len(tr.Payload) + 4，实测得出）。
// 该式内部即含自适应末组 parity（min(M2Cap, kLast)），尺寸对不上即布局错。
func assertV3FileSize(t *testing.T, f *os.File, m2cap int, cc int64) {
	t.Helper()
	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	tr := trailerOf(t, f)
	if tr.Version != format.FormatVersionV3 {
		t.Fatalf("trailer version=%d want %d", tr.Version, format.FormatVersionV3)
	}
	trailerLen := int64(format.TrailerFixed + len(tr.Payload) + 4)
	spec := layout.SpecV3(int64(m2cap))
	want := spec.TotalBlobCount(cc)*layout.BlobDiskSize + trailerLen
	if fi.Size() != want {
		t.Fatalf("file size=%d want %d (blobs=%d, trailerLen=%d)", fi.Size(), want, spec.TotalBlobCount(cc), trailerLen)
	}
}

// TestV3RoundTrip 核心往返矩阵：m2cap ∈ {64,32,16} × 明文字形。
// 覆盖的自适应边界：
//   - 3ch+1234：cc=4，末组 kLast=4 < m2cap → 末组 parity 收紧为 4；
//   - 64ch+999：cc=64，kLast=64 = m2cap 边界（m2cap=64 时 min(64,64)=64）；
//   - 128ch-full：单满组，parity = m2cap（满组生效）；
//   - 129ch+7：满组+1，末组 kLast=1 → 末组 parity = min(m2cap,1) = 1
//     （TestV3GroupBoundary 的边界即此例：尺寸断言 + 显式 GroupParity 双重验证，故不单列）。
//
// 128/129 块大用例只在 m2cap=32 跑一遍（控制总耗时 ~25s 内）。
func TestV3RoundTrip(t *testing.T) {
	cases := []struct {
		name string // 明文字形
		n    int    // 明文总长
		cc   int64  // 期望块数
		big  bool   // 大用例（128/129 块）：仅 m2cap=32 执行
	}{
		{"1chunk", layout.ChunkPlainSize, 1, false},
		{"3ch+1234", 3*layout.ChunkPlainSize + 1234, 4, false},
		{"64ch+999", 63*layout.ChunkPlainSize + 999, 64, false},
		{"128ch-full", 128 * layout.ChunkPlainSize, 128, true},
		{"129ch+7", 128*layout.ChunkPlainSize + 7, 129, true},
	}
	for _, m2cap := range []int{64, 32, 16} {
		for ci, tc := range cases {
			if tc.big && m2cap != 32 {
				continue
			}
			t.Run(fmt.Sprintf("m%d/%s", m2cap, tc.name), func(t *testing.T) {
				plain := testutil.MakePlain(tc.n, int64(m2cap*1000+ci*31+1))
				f := writeVaultOpt(t, plain, secvault.WithFileParity(m2cap))

				r, err := secvault.Open(f, testutil.TestKey)
				if err != nil {
					t.Fatalf("Open: %v", err)
				}
				if r.PlainSize() != int64(len(plain)) {
					t.Fatalf("PlainSize=%d want %d", r.PlainSize(), len(plain))
				}
				if r.ChunkCount() != tc.cc {
					t.Fatalf("ChunkCount=%d want %d", r.ChunkCount(), tc.cc)
				}
				// 尺寸断言（含 trailer 实测）：文件尾布局必须与 SpecV3 数学一致
				assertV3FileSize(t, f, m2cap, tc.cc)

				// 全量读 + 逐块 ReadChunkAt 交叉验证
				testutil.AssertPlain(t, r, plain)
				for idx := int64(0); idx < tc.cc; idx++ {
					start := idx * layout.ChunkPlainSize
					end := min(int64(len(plain)), start+layout.ChunkPlainSize)
					got, err := r.ReadChunkAt(idx, nil)
					if err != nil {
						t.Fatalf("ReadChunkAt(%d): %v", idx, err)
					}
					if !bytes.Equal(got, plain[start:end]) {
						t.Fatalf("chunk %d mismatch", idx)
					}
				}

				// 满组+1 边界（TestV3GroupBoundary 语义在此验证）：
				// 末组 kLast=1 时末组 parity = min(m2cap,1) = 1，绝非 m2cap/64。
				if tc.cc == 129 {
					spec := layout.SpecV3(int64(m2cap))
					if got := spec.GroupParity(1, r.ChunkCount()); got != 1 {
						t.Fatalf("last-group parity=%d want 1（自适应 min 收紧到 kLast）", got)
					}
				}
			})
		}
	}
}

// TestV3AdaptiveSmallerThanV2 同一明文下 v3 自适应末组比 v2 更小：
// cc=4 时 v2 末组仍写 64 个 parity blob（4+64=68 blobs），
// v3(m2cap=64) 末组收紧为 min(64,4)=4（4+4=8 blobs），尺寸显著更小且同样可读。
func TestV3AdaptiveSmallerThanV2(t *testing.T) {
	n := 3*layout.ChunkPlainSize + 1234 // cc=4，末组 kLast=4
	plain := testutil.MakePlain(n, 500)
	f2 := writeVaultOpt(t, plain)                              // 缺省 v2
	f3 := writeVaultOpt(t, plain, secvault.WithFileParity(64)) // v3, m2cap=64

	if tr := trailerOf(t, f2); tr.Version != format.FormatVersion {
		t.Fatalf("default trailer version=%d want %d", tr.Version, format.FormatVersion)
	}
	if tr := trailerOf(t, f3); tr.Version != format.FormatVersionV3 {
		t.Fatalf("v3 trailer version=%d want %d", tr.Version, format.FormatVersionV3)
	}
	st2, err := f2.Stat()
	if err != nil {
		t.Fatal(err)
	}
	st3, err := f3.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if st3.Size() >= st2.Size() {
		t.Fatalf("v3 size=%d not smaller than v2 size=%d", st3.Size(), st2.Size())
	}
	// 两者都必须完整往返
	for i, f := range []*os.File{f2, f3} {
		r, err := secvault.Open(f, testutil.TestKey)
		if err != nil {
			t.Fatalf("v%d Open: %v", i, err)
		}
		testutil.AssertPlain(t, r, plain)
	}
}

// TestV3Manifest v3 容器 trailer/manifest 元数据：
// trailer.Version=3；manifest 密文可解，Version=3 且 M2=m2cap（ResolveSpec 据此分支到 v3）。
func TestV3Manifest(t *testing.T) {
	const m2cap = 32
	plain := testutil.MakePlain(2*layout.ChunkPlainSize+100, 900)
	f := writeVaultOpt(t, plain, secvault.WithFileParity(m2cap))

	tr := trailerOf(t, f)
	if tr.Version != format.FormatVersionV3 {
		t.Fatalf("trailer version=%d want %d", tr.Version, format.FormatVersionV3)
	}
	// 按 engine.Open 的路径解密 manifest：HKDF → AES-GCM → JSON
	manAEAD, err := crypto.NewGCM(crypto.DeriveKey(testutil.TestKey, tr.FileID, "secvault/manifest/v1"))
	if err != nil {
		t.Fatal(err)
	}
	mb, err := manAEAD.Open(nil, tr.Nonce, tr.Payload, nil)
	if err != nil {
		t.Fatalf("manifest decrypt: %v", err)
	}
	var man format.Manifest
	if err := json.Unmarshal(mb, &man); err != nil {
		t.Fatalf("manifest json: %v", err)
	}
	if man.Version != format.FormatVersionV3 {
		t.Fatalf("manifest version=%d want %d", man.Version, format.FormatVersionV3)
	}
	if man.M2 != m2cap {
		t.Fatalf("manifest M2=%d want %d", man.M2, m2cap)
	}
	if sp := man.ResolveSpec(); sp.Version != format.FormatVersionV3 || sp.M2Cap != int64(m2cap) {
		t.Fatalf("ResolveSpec=%+v want {3 %d}", sp, m2cap)
	}
}

// TestV3Corruption v3 布局下的损坏修复（块内 / 文件级两级路径）。
// 文件为 2 块（单组 kLast=2）：组内 parity = min(32,2) = 2 个 blob。
func TestV3Corruption(t *testing.T) {
	const m2cap = 32
	plain := testutil.MakePlain(2*layout.ChunkPlainSize+100, 1100)
	spec := layout.SpecV3(m2cap)

	// 关键路径：130 槽破坏 > 块内 RS(256,128) 极限 → 文件级重建
	// （组内 2 数据 + 2 parity，RS(2,2) 容 1 erasure，读路径透明重建）。
	t.Run("file-level-rebuild-130slots", func(t *testing.T) {
		f := writeVaultOpt(t, plain, secvault.WithFileParity(m2cap))
		for i := int64(0); i < 130; i++ {
			corruptV3Slot(t, f, spec, 0, i, int(i*17+5)%layout.ShardSize)
		}
		r, err := secvault.Open(f, testutil.TestKey)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		testutil.AssertPlain(t, r, plain)
	})

	// 块内修复：5 槽破坏 ≤128，块内 RS 直接救回，不触达文件级。
	t.Run("intra-repair-5slots", func(t *testing.T) {
		f := writeVaultOpt(t, plain, secvault.WithFileParity(m2cap))
		for i := int64(0); i < 5; i++ {
			corruptV3Slot(t, f, spec, 0, i, int(i*37+11)%layout.ShardSize)
		}
		r, err := secvault.Open(f, testutil.TestKey)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		testutil.AssertPlain(t, r, plain)
	})
}

// corruptV3Slot 按 v3 布局（data-first）翻转 (chunk, slot) 槽内载荷区字节
// （inner ∈ [0,4096) 避开 tag 区；testutil.CorruptSlot 走 SpecV2 偏移，v3 不可用）。
func corruptV3Slot(t *testing.T, f *os.File, spec layout.Spec, chunk, slot int64, inner int) {
	t.Helper()
	if inner < 0 || inner >= layout.ShardSize {
		t.Fatalf("inner %d out of payload range", inner)
	}
	var b [1]byte
	off := spec.DataBlobOffset(chunk) + slot*layout.SlotSize + int64(inner)
	if _, err := f.ReadAt(b[:], off); err != nil {
		t.Fatalf("read @%d: %v", off, err)
	}
	b[0] ^= 0xFF
	if _, err := f.WriteAt(b[:], off); err != nil {
		t.Fatalf("write @%d: %v", off, err)
	}
}
