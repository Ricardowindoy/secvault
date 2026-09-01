package secvault_test

// gcm-only scheme（v3 批次1）单元测试（DESIGN-v3-phase2 §2.7）。
//
// 覆盖：WithRePull 往返（全量读 / ReadAt 切片 / ReadChunkAt(0)）、文件尺寸与
// GCMOnlySize 公式一致、manifest 元数据（scheme=gcm + rs-dual 字段为零）、
// 损坏检测（GCM.Open 失败 → ErrGCMOnlyCorrupted，errors.Is 可匹配；
// Verify/Scrub 报告 ChunksLost=[0] 且 Scrub 不回写）、option 互斥（后写覆盖前写）、
// 尺寸边界（0 / 1B / 1MB 界）。复用 v3_test.go 的 writeVaultOpt/trailerOf 助手。

import (
	"bytes"
	"encoding/json"
	"errors"
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

// decryptManifest 按 engine.Open 的路径解密 trailer 内的 manifest。
func decryptManifest(t *testing.T, tr *format.Trailer) *format.Manifest {
	t.Helper()
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
	return &man
}

// gcmTrailerLen 实测 trailerLen（TrailerFixed + manifest 密文 + CRC4）。
func gcmTrailerLen(t *testing.T, f *os.File) int64 {
	t.Helper()
	tr := trailerOf(t, f)
	return int64(format.TrailerFixed + len(tr.Payload) + 4)
}

// assertGCMFileSize 断言文件尺寸与 gcm-only 布局数学严格一致：
// size == GCMOnlyPayloadSize(plainSize) + trailerLen（trailerLen 实测得出）。
func assertGCMFileSize(t *testing.T, f *os.File, plainSize int64) {
	t.Helper()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	trailerLen := gcmTrailerLen(t, f)
	if want := layout.GCMOnlySize(plainSize, trailerLen); fi.Size() != want {
		t.Fatalf("file size=%d want %d (plainSize=%d trailerLen=%d)", fi.Size(), want, plainSize, trailerLen)
	}
}

// readFileBytes 读回整个文件内容（Scrub 前后对比用）。
func readFileBytes(t *testing.T, f *os.File) []byte {
	t.Helper()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, fi.Size())
	if _, err := f.ReadAt(buf, 0); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	return buf
}

// TestGCMOnlyRoundTrip 往返矩阵：KB 级 ~ 近 1MB。
// 全量读 + ReadChunkAt(0) 返回全部 + ReadAt 奇偏移切片 + 越界/负偏移语义。
func TestGCMOnlyRoundTrip(t *testing.T) {
	sizes := []int{
		1 << 10,               // KB 级
		64 << 10,              // 64KB
		layout.ChunkPlainSize, // 近 1MB（rs-dual 单块明文容量界）
	}
	for i, n := range sizes {
		t.Run(fmt.Sprintf("n%d", n), func(t *testing.T) {
			plain := testutil.MakePlain(n, int64(7000+i))
			f := writeVaultOpt(t, plain, secvault.WithRePull())

			r, err := secvault.Open(f, testutil.TestKey)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if r.PlainSize() != int64(n) {
				t.Fatalf("PlainSize=%d want %d", r.PlainSize(), n)
			}
			assertGCMFileSize(t, f, int64(n))

			// 全量读
			testutil.AssertPlain(t, r, plain)

			// ReadChunkAt(0) 返回全部
			got, err := r.ReadChunkAt(0, nil)
			if err != nil {
				t.Fatalf("ReadChunkAt(0): %v", err)
			}
			if !bytes.Equal(got, plain) {
				t.Fatal("ReadChunkAt(0) mismatch")
			}

			// ReadChunkAt(1) 越界（单 blob 无分块，仅 index 0 合法）
			if _, err := r.ReadChunkAt(1, nil); err == nil {
				t.Fatal("ReadChunkAt(1): expected out-of-range error")
			}

			// ReadAt 奇偏移切片
			off := int64(n / 3)
			buf := make([]byte, n/3+1)
			readN, err := r.ReadAt(buf, off)
			if err != nil && err != io.EOF {
				t.Fatalf("ReadAt @%d: %v", off, err)
			}
			if readN != len(buf) || !bytes.Equal(buf, plain[off:off+int64(len(buf))]) {
				t.Fatalf("ReadAt @%d: n=%d want %d", off, readN, len(buf))
			}

			// ReadAt 越界 / 负偏移
			if rn, err := r.ReadAt([]byte{0}, int64(n)); rn != 0 || err != io.EOF {
				t.Fatalf("past-end: n=%d err=%v", rn, err)
			}
			if _, err := r.ReadAt(make([]byte, 1), -1); !errors.Is(err, secvault.ErrNegativeOffset) {
				t.Fatalf("negative offset: %v", err)
			}
		})
	}
}

// TestGCMOnlySize 文件尺寸 == GCMOnlySize(plainSize, trailerLen)，覆盖尺寸边界。
func TestGCMOnlySize(t *testing.T) {
	for _, n := range []int{0, 1, 16, 1000, layout.ChunkPlainSize} {
		t.Run(fmt.Sprintf("n%d", n), func(t *testing.T) {
			plain := testutil.MakePlain(n, int64(8000+n))
			f := writeVaultOpt(t, plain, secvault.WithRePull())
			assertGCMFileSize(t, f, int64(n))
			if _, err := secvault.Open(f, testutil.TestKey); err != nil {
				t.Fatalf("Open: %v", err)
			}
		})
	}
}

// TestGCMOnlyManifest trailer/manifest 元数据：trailer.Version=3，
// manifest.Scheme="gcm"、PlainSize 一致、rs-dual 专有字段全部为零。
func TestGCMOnlyManifest(t *testing.T) {
	plain := testutil.MakePlain(5000, 8123)
	f := writeVaultOpt(t, plain, secvault.WithRePull())

	tr := trailerOf(t, f)
	if tr.Version != format.FormatVersionV3 {
		t.Fatalf("trailer version=%d want %d", tr.Version, format.FormatVersionV3)
	}
	man := decryptManifest(t, tr)
	if man.Version != format.FormatVersionV3 {
		t.Fatalf("manifest version=%d want %d", man.Version, format.FormatVersionV3)
	}
	if man.Scheme != string(format.SchemeGCMOnly) {
		t.Fatalf("manifest scheme=%q want %q", man.Scheme, format.SchemeGCMOnly)
	}
	if man.PlainSize != int64(len(plain)) {
		t.Fatalf("manifest PlainSize=%d want %d", man.PlainSize, len(plain))
	}
	if got := man.ResolveScheme(); got != format.SchemeGCMOnly {
		t.Fatalf("ResolveScheme=%q want %q", got, format.SchemeGCMOnly)
	}
	// gcm-only 无块/组概念：rs-dual 专有字段必须为零（JSON 省略或 0 值）
	if man.K != 0 || man.M != 0 || man.K2 != 0 || man.M2 != 0 ||
		man.ShardSize != 0 || man.ChunkPlain != 0 || man.ChunkCount != 0 ||
		man.KStrong != 0 || man.MStrong != 0 {
		t.Fatalf("rs-dual-only fields must be zero: %+v", man)
	}
}

// TestGCMOnlyCorruption 翻转正文区 1 字节（密文 / 头部 nonce 区）→
// 读路径报 ErrGCMOnlyCorrupted（errors.Is 可匹配）；Verify/Scrub 报告
// ChunksLost=[0] 且 Scrub 不回写（文件字节不变）。
func TestGCMOnlyCorruption(t *testing.T) {
	plain := testutil.MakePlain(100000, 8200)

	t.Run("ciphertext-flip", func(t *testing.T) {
		f := writeVaultOpt(t, plain, secvault.WithRePull())
		testutil.FlipByte(t, f, layout.GCMHeaderSize+int64(len(plain))/2)
		r, err := secvault.Open(f, testutil.TestKey)
		if err != nil {
			t.Fatalf("Open (manifest intact): %v", err)
		}
		if _, err := r.ReadChunkAt(0, nil); !errors.Is(err, secvault.ErrGCMOnlyCorrupted) {
			t.Fatalf("ReadChunkAt: got %v, want ErrGCMOnlyCorrupted", err)
		}
		if _, err := r.ReadAt(make([]byte, 16), 0); !errors.Is(err, secvault.ErrGCMOnlyCorrupted) {
			t.Fatalf("ReadAt: got %v, want ErrGCMOnlyCorrupted", err)
		}
	})

	t.Run("header-flip", func(t *testing.T) {
		f := writeVaultOpt(t, plain, secvault.WithRePull())
		testutil.FlipByte(t, f, 5) // 16B 头内部（magic 之后的 nonce 区，受 AAD 保护）
		r, err := secvault.Open(f, testutil.TestKey)
		if err != nil {
			t.Fatalf("Open (manifest intact): %v", err)
		}
		if _, err := r.ReadChunkAt(0, nil); !errors.Is(err, secvault.ErrGCMOnlyCorrupted) {
			t.Fatalf("got %v, want ErrGCMOnlyCorrupted", err)
		}
	})

	t.Run("scrub-report-no-rewrite", func(t *testing.T) {
		f := writeVaultOpt(t, plain, secvault.WithRePull())
		testutil.FlipByte(t, f, layout.GCMHeaderSize+int64(len(plain))/2)
		before := readFileBytes(t, f)

		rep, err := secvault.Verify(f, testutil.TestKey, secvault.Options{})
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if rep.ChunksTotal != 1 || rep.ChunksClean != 0 ||
			len(rep.ChunksLost) != 1 || rep.ChunksLost[0] != 0 {
			t.Fatalf("Verify report: %+v", rep)
		}
		rep2, err := secvault.Scrub(f, testutil.TestKey, secvault.Options{})
		if err != nil {
			t.Fatalf("Scrub: %v", err)
		}
		if rep2.ChunksTotal != 1 || len(rep2.ChunksLost) != 1 || rep2.ChunksLost[0] != 0 {
			t.Fatalf("Scrub report: %+v", rep2)
		}
		if after := readFileBytes(t, f); !bytes.Equal(before, after) {
			t.Fatal("Scrub must not rewrite gcm-only container (no repair path)")
		}
	})

	t.Run("scrub-clean", func(t *testing.T) {
		f := writeVaultOpt(t, plain, secvault.WithRePull())
		rep, err := secvault.Verify(f, testutil.TestKey, secvault.Options{})
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if rep.ChunksTotal != 1 || rep.ChunksClean != 1 || len(rep.ChunksLost) != 0 {
			t.Fatalf("clean Verify report: %+v", rep)
		}
	})
}

// TestGCMOnlyTrailerOption option 语义：缺省（无 option）仍写 v2；
// WithRePull 写 v3 gcm；与 WithFileParity 互斥时以最后一个 option 为准
//（后写覆盖前写，两个方向都验证）。
func TestGCMOnlyTrailerOption(t *testing.T) {
	plain := testutil.MakePlain(3000, 8300)

	// 缺省：v2（trailer version=2）
	f := writeVaultOpt(t, plain)
	if tr := trailerOf(t, f); tr.Version != format.FormatVersion {
		t.Fatalf("default trailer version=%d want %d", tr.Version, format.FormatVersion)
	}

	// WithRePull：v3 + scheme=gcm
	fg := writeVaultOpt(t, plain, secvault.WithRePull())
	if tr := trailerOf(t, fg); tr.Version != format.FormatVersionV3 {
		t.Fatalf("repull trailer version=%d want %d", tr.Version, format.FormatVersionV3)
	}
	if man := decryptManifest(t, trailerOf(t, fg)); man.Scheme != string(format.SchemeGCMOnly) {
		t.Fatalf("repull scheme=%q want %q", man.Scheme, format.SchemeGCMOnly)
	}

	// WithRePull 后接 WithFileParity → 最后一个生效：rs-dual v3（scheme 省略、M2=32）
	fd := writeVaultOpt(t, plain, secvault.WithRePull(), secvault.WithFileParity(32))
	if tr := trailerOf(t, fd); tr.Version != format.FormatVersionV3 {
		t.Fatalf("fileparity-after trailer version=%d want %d", tr.Version, format.FormatVersionV3)
	}
	if man := decryptManifest(t, trailerOf(t, fd)); man.Scheme != "" || man.M2 != 32 {
		t.Fatalf("fileparity-after manifest: scheme=%q m2=%d, want scheme=\"\" m2=32", man.Scheme, man.M2)
	}

	// WithFileParity 后接 WithRePull → 最后一个生效：gcm
	fg2 := writeVaultOpt(t, plain, secvault.WithFileParity(32), secvault.WithRePull())
	if man := decryptManifest(t, trailerOf(t, fg2)); man.Scheme != string(format.SchemeGCMOnly) {
		t.Fatalf("repull-after scheme=%q want %q", man.Scheme, format.SchemeGCMOnly)
	}
}

// TestGCMOnlyEmpty 空文件边界：plainSize=0 容许（ps=0，载荷=16B 头+16B tag），
// 可 Open、ReadChunkAt(0) 返回空、ReadAt 报 EOF、尺寸符合公式。
func TestGCMOnlyEmpty(t *testing.T) {
	f := writeVaultOpt(t, nil, secvault.WithRePull())
	r, err := secvault.Open(f, testutil.TestKey)
	if err != nil {
		t.Fatalf("Open (ps=0 must be allowed): %v", err)
	}
	if r.PlainSize() != 0 {
		t.Fatalf("PlainSize=%d want 0", r.PlainSize())
	}
	got, err := r.ReadChunkAt(0, nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("ReadChunkAt(0): n=%d err=%v", len(got), err)
	}
	if n, err := r.ReadAt(make([]byte, 4), 0); n != 0 || err != io.EOF {
		t.Fatalf("ReadAt on empty: n=%d err=%v", n, err)
	}
	assertGCMFileSize(t, f, 0)
}
