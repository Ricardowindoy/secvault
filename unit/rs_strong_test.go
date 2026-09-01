package secvault_test

// rs-strong scheme（v3 批次2）单元测试（DESIGN-v3-phase2 §2.10）。
//
// 覆盖：WithStrongRS 往返（全量读 / ReadAt 切片 / ReadChunkAt(0)）、文件尺寸与
// StrongSize 公式一致（含 shardSize 向上取整边界）、manifest 元数据
//（scheme=rs-strong + K=32/M=64 + 变长 ShardSize + KStrong/MStrong 冗余记录 +
// ChunkCount=0）、损坏矩阵（坏 1..64 槽 RS(32,64) 重建成功，65 槽不可恢复，
// 66.7% 容错边界）、Scrub 逐槽修复回写（坏 ≤64 槽重建后回写载荷+tag，再 Verify
// 干净）。复用 v3_test.go 的 writeVaultOpt/trailerOf 与 gcm_only_test.go 的
// decryptManifest/gcmTrailerLen/readFileBytes 助手（同包）。

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"secvault"
	"secvault/internal/format"
	"secvault/internal/layout"
	"secvault/internal/testutil"
)

// corruptStrongSlot 翻转 rs-strong (slot) 槽内 payload 的 inner 偏移字节
//（inner ∈ [0, StrongShardSize)，避开 16B tag 区）。testutil.CorruptSlot 走
// SpecV2 偏移，对 rs-strong 单 blob 布局不可用，故独立实现。
// 槽 slot 的文件偏移 = slot × StrongSlotSize(plainSize) = slot × (shardSize + TagSize)。
func corruptStrongSlot(t *testing.T, f *os.File, plainSize int64, slot, inner int) {
	t.Helper()
	shardSize := layout.StrongShardSize(plainSize)
	if inner < 0 || int64(inner) >= shardSize {
		t.Fatalf("inner %d out of payload range [0,%d)", inner, shardSize)
	}
	off := int64(slot)*layout.StrongSlotSize(plainSize) + int64(inner)
	testutil.FlipByte(t, f, off)
}

// assertStrongFileSize 断言文件尺寸与 rs-strong 布局数学严格一致：
// size == StrongSize(plainSize, trailerLen) = StrongPayloadSize(plainSize) + trailerLen
// （trailerLen 实测得出 = TrailerFixed + len(Payload) + 4；trailer 帧结构 v2/v3 一致，
// 复用 gcm_only_test.go 的 gcmTrailerLen）。尺寸对不上即布局错。
func assertStrongFileSize(t *testing.T, f *os.File, plainSize int64) {
	t.Helper()
	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	trailerLen := gcmTrailerLen(t, f) // trailer 帧结构通用
	if want := layout.StrongSize(plainSize, trailerLen); fi.Size() != want {
		t.Fatalf("file size=%d want %d (plainSize=%d trailerLen=%d shardSize=%d)",
			fi.Size(), want, plainSize, trailerLen, layout.StrongShardSize(plainSize))
	}
}

// TestRSStrongRoundTrip 往返矩阵：1B ~ 1MB（分界点，WithStrongRS 强制 rs-strong）。
// 全量读 + ReadChunkAt(0) 返回全部 + ReadChunkAt(1) 越界 + ReadAt 奇偏移切片。
func TestRSStrongRoundTrip(t *testing.T) {
	sizes := []int{
		1,                       // 最小：shardSize=ceil(49/32)=2
		100,                     // 百字节级
		layout.ShardSize,        // 4KB（shardSize 对齐边界）
		64 << 10,                // 64KB
		256 << 10,               // 256KB
		layout.ChunkPlainSize,   // 近 1MB（rs-dual 单块明文容量界，rs-strong 分界点）
	}
	for i, n := range sizes {
		t.Run(fmt.Sprintf("n%d", n), func(t *testing.T) {
			plain := testutil.MakePlain(n, int64(9000+i))
			f := writeVaultOpt(t, plain, secvault.WithStrongRS())

			r, err := secvault.Open(f, testutil.TestKey)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if r.PlainSize() != int64(n) {
				t.Fatalf("PlainSize=%d want %d", r.PlainSize(), n)
			}
			if r.ChunkCount() != 0 { // rs-strong 无分块
				t.Fatalf("ChunkCount=%d want 0", r.ChunkCount())
			}
			assertStrongFileSize(t, f, int64(n))

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

			// ReadChunkAt(1) 越界（单 blob 仅 index 0 合法）
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
			wantEnd := off + int64(len(buf))
			if wantEnd > int64(n) {
				wantEnd = int64(n)
			}
			if int64(readN) != wantEnd-off || !bytes.Equal(buf[:readN], plain[off:wantEnd]) {
				t.Fatalf("ReadAt @%d: n=%d want %d", off, readN, wantEnd-off)
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

// TestRSStrongSize 文件尺寸 == StrongSize(plainSize, trailerLen)，
// 覆盖 shardSize 向上取整边界。
//
// shardSize = ceil((HeaderSize + plainSize + TagSize) / KStrong) = ceil((32+ps+16)/32)。
// 边界点：
//   - ps=1:  dataLen=49, shardSize=2  (49/32=1.53→2)
//   - ps=16: dataLen=64, shardSize=2  (64/32=2 整除)
//   - ps=17: dataLen=65, shardSize=3  (65/32=2.03→3)
//   - ps=48: dataLen=96, shardSize=3  (96/32=3 整除)
//   - ps=49: dataLen=97, shardSize=4  (97/32=3.03→4)
func TestRSStrongSize(t *testing.T) {
	cases := []struct {
		n           int
		wantShardSz int64
	}{
		{1, 2},
		{16, 2},
		{17, 3},
		{48, 3},
		{49, 4},
		{1000, 33},  // (32+1000+16)/32 = 1048/32 = 32.75 → 33
		{layout.ChunkPlainSize, layout.StrongShardSize(layout.ChunkPlainSize)},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("n%d", c.n), func(t *testing.T) {
			plain := testutil.MakePlain(c.n, int64(9100+c.n))
			f := writeVaultOpt(t, plain, secvault.WithStrongRS())

			// shardSize 数学核对
			if got := layout.StrongShardSize(int64(c.n)); got != c.wantShardSz {
				t.Fatalf("StrongShardSize(%d)=%d want %d", c.n, got, c.wantShardSz)
			}
			assertStrongFileSize(t, f, int64(c.n))
			if _, err := secvault.Open(f, testutil.TestKey); err != nil {
				t.Fatalf("Open: %v", err)
			}
		})
	}
}

// TestRSStrongManifest trailer/manifest 元数据：trailer.Version=3；
// manifest 解密后 Scheme="rs-strong"、K=32、M=64、ShardSize==StrongShardSize(ps)
//（变长，随文件尺寸缩放）、KStrong=32、MStrong=64、ChunkCount=0、PlainSize 一致。
func TestRSStrongManifest(t *testing.T) {
	plain := testutil.MakePlain(5000, 9123) // shardSize=ceil((32+5000+16)/32)=ceil(5048/32)=158
	f := writeVaultOpt(t, plain, secvault.WithStrongRS())

	tr := trailerOf(t, f)
	if tr.Version != format.FormatVersionV3 {
		t.Fatalf("trailer version=%d want %d", tr.Version, format.FormatVersionV3)
	}
	man := decryptManifest(t, tr)
	if man.Version != format.FormatVersionV3 {
		t.Fatalf("manifest version=%d want %d", man.Version, format.FormatVersionV3)
	}
	if man.Scheme != string(format.SchemeRSStrong) {
		t.Fatalf("manifest scheme=%q want %q", man.Scheme, format.SchemeRSStrong)
	}
	if man.K != layout.KStrong || man.M != layout.MStrong {
		t.Fatalf("manifest K=%d M=%d want %d %d", man.K, man.M, layout.KStrong, layout.MStrong)
	}
	wantSS := int(layout.StrongShardSize(int64(len(plain))))
	if man.ShardSize != wantSS {
		t.Fatalf("manifest ShardSize=%d want %d (StrongShardSize)", man.ShardSize, wantSS)
	}
	if man.KStrong != layout.KStrong || man.MStrong != layout.MStrong {
		t.Fatalf("manifest KStrong=%d MStrong=%d want %d %d", man.KStrong, man.MStrong, layout.KStrong, layout.MStrong)
	}
	if man.ChunkCount != 0 {
		t.Fatalf("manifest ChunkCount=%d want 0 (no chunking)", man.ChunkCount)
	}
	if man.PlainSize != int64(len(plain)) {
		t.Fatalf("manifest PlainSize=%d want %d", man.PlainSize, len(plain))
	}
	if got := man.ResolveScheme(); got != format.SchemeRSStrong {
		t.Fatalf("ResolveScheme=%q want %q", got, format.SchemeRSStrong)
	}
	// rs-strong 无组概念：K2/M2/ChunkPlain 必须为零
	if man.K2 != 0 || man.M2 != 0 || man.ChunkPlain != 0 {
		t.Fatalf("rs-dual-only fields must be zero: K2=%d M2=%d ChunkPlain=%d", man.K2, man.M2, man.ChunkPlain)
	}
}

// TestRSStrongCorruptionMatrix 损坏矩阵：坏 1/8/16/32/63/64 槽 → RS(32,64) 重建成功
//（明文与原文 bytes.Equal）；坏 65 槽 → ErrChunkUnrecoverable（超出 66.7% 容错边界，
// errors.Is 可匹配）。逐步逼近极限 MStrong=64，验证容错边界。
func TestRSStrongCorruptionMatrix(t *testing.T) {
	plain := testutil.MakePlain(100000, 9200) // shardSize=ceil((32+100000+16)/32)=ceil(100048/32)=3127
	ps := int64(len(plain))
	shardSize := layout.StrongShardSize(ps)

	badCounts := []int{1, 8, 16, 32, 63, 64, 65}
	for _, nb := range badCounts {
		t.Run(fmt.Sprintf("bad%d", nb), func(t *testing.T) {
			f := writeVaultOpt(t, plain, secvault.WithStrongRS())
			// 翻转前 nb 个槽（0..nb-1）的 payload 区不同字节
			for i := 0; i < nb; i++ {
				inner := (i*7 + 3) % int(shardSize)
				corruptStrongSlot(t, f, ps, i, inner)
			}
			r, err := secvault.Open(f, testutil.TestKey)
			if err != nil {
				t.Fatalf("Open (manifest intact): %v", err)
			}
			if nb <= layout.MStrong {
				// ≤64 槽坏：RS(32,64) 重建成功，明文精确恢复
				testutil.AssertPlain(t, r, plain)
				// ReadChunkAt(0) 也应成功
				got, err := r.ReadChunkAt(0, nil)
				if err != nil {
					t.Fatalf("ReadChunkAt(0) after rebuild: %v", err)
				}
				if !bytes.Equal(got, plain) {
					t.Fatalf("chunk 0 mismatch after rebuild (bad %d slots)", nb)
				}
			} else {
				// 65 槽坏：超出 RS(32,64) 容错（MStrong=64），不可恢复
				_, err := r.ReadChunkAt(0, nil)
				if !errors.Is(err, secvault.ErrChunkUnrecoverable) {
					t.Fatalf("bad %d slots: got %v, want ErrChunkUnrecoverable", nb, err)
				}
				// ReadAt 同样不可恢复
				if _, err := r.ReadAt(make([]byte, 16), 0); !errors.Is(err, secvault.ErrChunkUnrecoverable) {
					t.Fatalf("ReadAt bad %d slots: got %v, want ErrChunkUnrecoverable", nb, err)
				}
			}
		})
	}
}

// TestRSStrongScrubRepair Scrub 逐槽修复回写：坏 5 槽 → Scrub RS 重建 + 回写
// 载荷与重算 tag → 再 Verify 干净（ChunksClean=1）。整文件 = 1 个"块"
//（ChunksTotal=1，复用 rs-dual 的 Report 语义）。
func TestRSStrongScrubRepair(t *testing.T) {
	plain := testutil.MakePlain(50000, 9300) // shardSize=ceil((32+50000+16)/32)=ceil(50048/32)=1565
	ps := int64(len(plain))
	shardSize := layout.StrongShardSize(ps)

	t.Run("repair-and-rewrite", func(t *testing.T) {
		f := writeVaultOpt(t, plain, secvault.WithStrongRS())
		badSlots := []int{0, 10, 20, 30, 40}
		for _, s := range badSlots {
			corruptStrongSlot(t, f, ps, s, (s*13+5)%int(shardSize))
		}

		// Verify（只读）：5 槽坏，可修复（ChunksRepaired=1，ShardsBad=5，ShardsRepaired=5）
		rep, err := secvault.Verify(f, testutil.TestKey, secvault.Options{})
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if rep.ChunksTotal != 1 || rep.ChunksClean != 0 || rep.ChunksRepaired != 1 ||
			rep.ShardsBad != 5 || rep.ShardsRepaired != 5 || len(rep.ChunksLost) != 0 {
			t.Fatalf("Verify report: %+v", rep)
		}

		// Scrub（回写）：重建坏槽 + 回写载荷与重算 tag
		before := readFileBytes(t, f)
		rep2, err := secvault.Scrub(f, testutil.TestKey, secvault.Options{})
		if err != nil {
			t.Fatalf("Scrub: %v", err)
		}
		if rep2.ChunksTotal != 1 || rep2.ChunksRepaired != 1 || rep2.ShardsRepaired != 5 || len(rep2.ChunksLost) != 0 {
			t.Fatalf("Scrub report: %+v", rep2)
		}
		// Scrub 回写了坏槽 → 文件字节应变化（5 槽被修复）
		if after := readFileBytes(t, f); bytes.Equal(before, after) {
			t.Fatal("Scrub did not rewrite corrupted slots")
		}

		// 再 Verify：5 槽已修复（tag 重算），应干净
		rep3, err := secvault.Verify(f, testutil.TestKey, secvault.Options{})
		if err != nil {
			t.Fatalf("post-Scrub Verify: %v", err)
		}
		if rep3.ChunksTotal != 1 || rep3.ChunksClean != 1 || rep3.ShardsBad != 0 || len(rep3.ChunksLost) != 0 {
			t.Fatalf("post-Scrub report not clean: %+v", rep3)
		}

		// 修复后能正常读取
		r, err := secvault.Open(f, testutil.TestKey)
		if err != nil {
			t.Fatalf("Open after Scrub: %v", err)
		}
		testutil.AssertPlain(t, r, plain)
	})

	t.Run("unrecoverable-no-rewrite", func(t *testing.T) {
		// 坏 65 槽：超出 RS(32,64) 容错，Scrub 报 ChunksLost=[0]，不回写
		f := writeVaultOpt(t, plain, secvault.WithStrongRS())
		for i := 0; i < 65; i++ {
			corruptStrongSlot(t, f, ps, i, (i*7+3)%int(shardSize))
		}
		before := readFileBytes(t, f)
		rep, err := secvault.Scrub(f, testutil.TestKey, secvault.Options{})
		if err != nil {
			t.Fatalf("Scrub: %v", err)
		}
		if rep.ChunksTotal != 1 || len(rep.ChunksLost) != 1 || rep.ChunksLost[0] != 0 {
			t.Fatalf("Scrub report (unrecoverable): %+v", rep)
		}
		if after := readFileBytes(t, f); !bytes.Equal(before, after) {
			t.Fatal("Scrub must not rewrite unrecoverable rs-strong container")
		}
	})

	t.Run("clean", func(t *testing.T) {
		f := writeVaultOpt(t, plain, secvault.WithStrongRS())
		rep, err := secvault.Verify(f, testutil.TestKey, secvault.Options{})
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if rep.ChunksTotal != 1 || rep.ChunksClean != 1 || rep.ShardsBad != 0 || len(rep.ChunksLost) != 0 {
			t.Fatalf("clean Verify report: %+v", rep)
		}
	})
}

// TestRSStrongTrailerOption option 语义：缺省写 v2；WithStrongRS 写 v3 rs-strong；
// 与 WithRePull/WithFileParity 互斥时以最后一个 option 为准（后写覆盖前写）。
func TestRSStrongTrailerOption(t *testing.T) {
	plain := testutil.MakePlain(3000, 9400)

	// WithStrongRS：v3 + scheme=rs-strong
	f := writeVaultOpt(t, plain, secvault.WithStrongRS())
	if tr := trailerOf(t, f); tr.Version != format.FormatVersionV3 {
		t.Fatalf("strong trailer version=%d want %d", tr.Version, format.FormatVersionV3)
	}
	if man := decryptManifest(t, trailerOf(t, f)); man.Scheme != string(format.SchemeRSStrong) {
		t.Fatalf("strong scheme=%q want %q", man.Scheme, format.SchemeRSStrong)
	}

	// WithStrongRS 后接 WithRePull → 最后一个生效：gcm
	fg := writeVaultOpt(t, plain, secvault.WithStrongRS(), secvault.WithRePull())
	if man := decryptManifest(t, trailerOf(t, fg)); man.Scheme != string(format.SchemeGCMOnly) {
		t.Fatalf("repull-after scheme=%q want %q", man.Scheme, format.SchemeGCMOnly)
	}

	// WithRePull 后接 WithStrongRS → 最后一个生效：rs-strong
	fs := writeVaultOpt(t, plain, secvault.WithRePull(), secvault.WithStrongRS())
	if man := decryptManifest(t, trailerOf(t, fs)); man.Scheme != string(format.SchemeRSStrong) {
		t.Fatalf("strong-after scheme=%q want %q", man.Scheme, format.SchemeRSStrong)
	}

	// WithFileParity 后接 WithStrongRS → 最后一个生效：rs-strong
	fs2 := writeVaultOpt(t, plain, secvault.WithFileParity(32), secvault.WithStrongRS())
	if man := decryptManifest(t, trailerOf(t, fs2)); man.Scheme != string(format.SchemeRSStrong) {
		t.Fatalf("strong-after-fileparity scheme=%q want %q", man.Scheme, format.SchemeRSStrong)
	}
}

// TestRSStrongEmpty 空文件边界：plainSize=0 容许（shardSize=ceil((32+0+16)/32)=2，
// 96 槽 × (2+16)B = 1728B payload），可 Open、ReadChunkAt(0) 返回空、ReadAt 报
// EOF、尺寸符合 StrongSize 公式。与 TestGCMOnlyEmpty 对称覆盖 ps=0 边界。
func TestRSStrongEmpty(t *testing.T) {
	f := writeVaultOpt(t, nil, secvault.WithStrongRS())
	r, err := secvault.Open(f, testutil.TestKey)
	if err != nil {
		t.Fatalf("Open (ps=0 must be allowed): %v", err)
	}
	if r.PlainSize() != 0 {
		t.Fatalf("PlainSize=%d want 0", r.PlainSize())
	}
	if r.ChunkCount() != 0 {
		t.Fatalf("ChunkCount=%d want 0", r.ChunkCount())
	}
	got, err := r.ReadChunkAt(0, nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("ReadChunkAt(0): n=%d err=%v", len(got), err)
	}
	if n, err := r.ReadAt(make([]byte, 4), 0); n != 0 || err != io.EOF {
		t.Fatalf("ReadAt on empty: n=%d err=%v", n, err)
	}
	// shardSize(0) = ceil((32+0+16)/32) = ceil(48/32) = 2
	if ss := layout.StrongShardSize(0); ss != 2 {
		t.Fatalf("StrongShardSize(0)=%d want 2", ss)
	}
	assertStrongFileSize(t, f, 0)
}

// TestRSStrongScrubRebuildParityIgnored rs-strong 单 blob 无文件级 parity，
// RebuildParity=true 应被忽略（DESIGN §3.5，行为同 false）：坏 5 槽 Scrub 修复
// 回写，不报错，ChunksRepaired=1；修复后再 Verify 干净。
func TestRSStrongScrubRebuildParityIgnored(t *testing.T) {
	plain := testutil.MakePlain(50000, 9500)
	ps := int64(len(plain))
	shardSize := layout.StrongShardSize(ps)
	f := writeVaultOpt(t, plain, secvault.WithStrongRS())
	for i := 0; i < 5; i++ {
		corruptStrongSlot(t, f, ps, i, (i*13+5)%int(shardSize))
	}
	rep, err := secvault.Scrub(f, testutil.TestKey, secvault.Options{RebuildParity: true})
	if err != nil {
		t.Fatalf("Scrub with RebuildParity=true: %v", err)
	}
	if rep.ChunksTotal != 1 || rep.ChunksRepaired != 1 || rep.ShardsRepaired != 5 || len(rep.ChunksLost) != 0 {
		t.Fatalf("Scrub (RebuildParity should be ignored): %+v", rep)
	}
	// 修复后应干净
	rep2, err := secvault.Verify(f, testutil.TestKey, secvault.Options{})
	if err != nil {
		t.Fatalf("post-Scrub Verify: %v", err)
	}
	if rep2.ChunksClean != 1 || rep2.ShardsBad != 0 {
		t.Fatalf("post-Scrub not clean: %+v", rep2)
	}
}
