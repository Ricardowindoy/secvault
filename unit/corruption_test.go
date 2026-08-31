package secvault_test

import (
	"errors"
	"fmt"
	"math/rand"
	"secvault"
	"secvault/internal/testutil"
	"testing"

	"secvault/internal/layout"
)

// TestSingleBitFlipSweep 逐个翻转采样槽位（数据+校验区），每次都在干净副本上：
// 读取必须完全恢复，Verify 必须精确报告 1 个坏 shard。
func TestSingleBitFlipSweep(t *testing.T) {
	plain := testutil.MakePlain(2*layout.ChunkPlainSize, 7)
	master := testutil.WriteVault(t, plain)

	type mut struct {
		chunk, slot int64
		inner       int
	}
	var muts []mut
	for slot := int64(0); slot < layout.ShardsPerBlob; slot += 16 { // 覆盖数据区与校验区
		muts = append(muts, mut{0, slot, int((slot * 37) % layout.ShardSize)})
	}
	for slot := int64(0); slot < layout.ShardsPerBlob; slot += 96 {
		muts = append(muts, mut{1, slot, int((slot * 53) % layout.ShardSize)})
	}
	for i, m := range muts {
		mf := testutil.NewMemFile()
		mf.Write(master.Bytes())
		testutil.CorruptSlot(t, mf, m.chunk, m.slot, m.inner)

		r, err := secvault.Open(mf, testutil.TestKey)
		if err != nil {
			t.Fatalf("mut %d: Open: %v", i, err)
		}
		testutil.AssertPlain(t, r, plain)

		rep, err := secvault.Verify(mf, testutil.TestKey, secvault.Options{})
		if err != nil {
			t.Fatalf("mut %d: Verify: %v", i, err)
		}
		if rep.ShardsBad != 1 || rep.ChunksRepaired != 1 || rep.ChunksClean != 1 || len(rep.ChunksLost) != 0 {
			t.Fatalf("mut %d (chunk%d slot%d): report %+v", i, m.chunk, m.slot, rep)
		}
	}
}

// TestTagCorruption 只破坏 tag 区 → 读取恢复（载荷完好，重建结果与原 tag 语义一致）。
func TestTagCorruption(t *testing.T) {
	plain := testutil.MakePlain(2*layout.ChunkPlainSize, 17)
	master := testutil.WriteVault(t, plain)
	for _, m := range []struct {
		chunk, slot int64
		inner       int
	}{{0, 0, 0}, {0, 100, 8}, {1, 383, 15}, {1, 256, 3}} {
		mf := testutil.NewMemFile()
		mf.Write(master.Bytes())
		testutil.CorruptTag(t, mf, m.chunk, m.slot, m.inner)
		r, err := secvault.Open(mf, testutil.TestKey)
		if err != nil {
			t.Fatal(err)
		}
		testutil.AssertPlain(t, r, plain)
	}
}

// TestParityOnlyCorruption 只坏块内校验区 → 数据无损，读取必须成功。
func TestParityOnlyCorruption(t *testing.T) {
	plain := testutil.MakePlain(2*layout.ChunkPlainSize, 19)
	master := testutil.WriteVault(t, plain)
	for _, slot := range []int64{256, 300, 340, 383} {
		mf := testutil.NewMemFile()
		mf.Write(master.Bytes())
		testutil.CorruptSlot(t, mf, 0, slot, int(slot*11%layout.ShardSize))
		testutil.CorruptSlot(t, mf, 1, slot, int(slot*13%layout.ShardSize))
		r, err := secvault.Open(mf, testutil.TestKey)
		if err != nil {
			t.Fatal(err)
		}
		testutil.AssertPlain(t, r, plain)
	}
}

// TestMaxIntraDamage 恰好 128 个坏 shard（块内纠错极限）：数据区 / 校验区 / 混合。
func TestMaxIntraDamage(t *testing.T) {
	plain := testutil.MakePlain(2*layout.ChunkPlainSize, 23)
	master := testutil.WriteVault(t, plain)
	variants := map[string][]int64{
		"data-only":   seq(0, 128),
		"parity-only": seq(256, 384),
		"mixed":       seq(0, 256), // 步长 2 取 128 个
	}
	for name, slots := range variants {
		t.Run(name, func(t *testing.T) {
			if name == "mixed" {
				slots = slots[:128] // 0,2,4,...,254
			}
			if len(slots) != layout.ParityShards {
				t.Fatalf("bad fixture: %d slots", len(slots))
			}
			mf := testutil.NewMemFile()
			mf.Write(master.Bytes())
			for i, slot := range slots {
				testutil.CorruptSlot(t, mf, 0, slot, (i*29+7)%layout.ShardSize)
			}
			r, err := secvault.Open(mf, testutil.TestKey)
			if err != nil {
				t.Fatal(err)
			}
			testutil.AssertPlain(t, r, plain)
		})
	}
}

func seq(lo, hi int64) []int64 {
	out := make([]int64, 0, hi-lo)
	for i := lo; i < hi; i++ {
		out = append(out, i)
	}
	return out
}

// TestBeyondIntraRescue 超出块内能力（130 坏 shard / 整块清零）→ 文件级重建救回。
func TestBeyondIntraRescue(t *testing.T) {
	plain := testutil.MakePlain(2*layout.ChunkPlainSize+9, 29)
	master := testutil.WriteVault(t, plain)

	t.Run("130 slots", func(t *testing.T) {
		mf := testutil.NewMemFile()
		mf.Write(master.Bytes())
		for i := int64(0); i < 130; i++ {
			testutil.CorruptSlot(t, mf, 0, i, int(i*31%layout.ShardSize))
		}
		r, err := secvault.Open(mf, testutil.TestKey)
		if err != nil {
			t.Fatal(err)
		}
		testutil.AssertPlain(t, r, plain)
		rep, err := secvault.Verify(mf, testutil.TestKey, secvault.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if rep.ChunksRebuilt != 1 || rep.ChunksRepaired != 0 {
			t.Fatalf("report: %+v", rep)
		}
	})

	t.Run("zeroed blob", func(t *testing.T) {
		mf := testutil.NewMemFile()
		mf.Write(master.Bytes())
		testutil.ZeroBlob(t, mf, 1)
		r, err := secvault.Open(mf, testutil.TestKey)
		if err != nil {
			t.Fatal(err)
		}
		testutil.AssertPlain(t, r, plain)
	})
}

// TestHeaderFieldCorruption 块头各字段（magic/序号/长度/nonce）损坏 → shard tag 拦截并重建。
func TestHeaderFieldCorruption(t *testing.T) {
	plain := testutil.MakePlain(layout.ChunkPlainSize+50, 31)
	master := testutil.WriteVault(t, plain)
	for _, inner := range []int{0, 5, 15, 25, 31} { // magic / index / plainLen / nonce 区
		mf := testutil.NewMemFile()
		mf.Write(master.Bytes())
		testutil.CorruptSlot(t, mf, 0, 0, inner)
		r, err := secvault.Open(mf, testutil.TestKey)
		if err != nil {
			t.Fatalf("inner %d: %v", inner, err)
		}
		testutil.AssertPlain(t, r, plain)
	}
}

// TestFileLevelCapacity 大容量边界（-short 跳过）：
// 整组毁 64 块 → Scrub 全部重建；毁 65 块 → 恰好 65 块判死，其余完好。
func TestFileLevelCapacity(t *testing.T) {
	if testing.Short() {
		t.Skip("large test")
	}
	const chunks = 130
	plain := testutil.MakePlain(chunks*layout.ChunkPlainSize, 91)
	p := testutil.DiskVault(t, plain)

	t.Run("destroy 64 -> all rebuilt", func(t *testing.T) {
		mf, err := osOpenRW(p)
		if err != nil {
			t.Fatal(err)
		}
		defer mf.Close()
		for c := int64(0); c < 64; c++ {
			testutil.ZeroBlob(t, mf, c)
		}
		rep, err := secvault.Scrub(mf, testutil.TestKey, secvault.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if rep.ChunksRebuilt != 64 || len(rep.ChunksLost) != 0 {
			t.Fatalf("report: %+v", rep)
		}
		assertDiskPlain(t, p, plain)
		rep2, err := secvault.Verify(mf, testutil.TestKey, secvault.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if rep2.ChunksClean != chunks {
			t.Fatalf("post-scrub not clean: %+v", rep2)
		}
	})

	t.Run("destroy 65 -> exactly 65 lost", func(t *testing.T) {
		mf, err := osOpenRW(p)
		if err != nil {
			t.Fatal(err)
		}
		defer mf.Close()
		// 重建容器（上一子测试已把前 64 块修复，这里重新写一份干净容器到新文件再破坏）
		p2 := testutil.DiskVault(t, plain)
		f2, err := osOpenRW(p2)
		if err != nil {
			t.Fatal(err)
		}
		defer f2.Close()
		for c := int64(0); c < 65; c++ {
			testutil.ZeroBlob(t, f2, c)
		}
		rep, err := secvault.Scrub(f2, testutil.TestKey, secvault.Options{RebuildParity: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.ChunksLost) != 65 || rep.ChunksRebuilt != 0 {
			t.Fatalf("report: %+v", rep)
		}
		for i, idx := range rep.ChunksLost {
			if idx != int64(i) {
				t.Fatalf("lost list wrong at %d: %d", i, idx)
			}
		}
		if rep.ChunksClean != chunks-65 {
			t.Fatalf("clean=%d want %d", rep.ChunksClean, chunks-65)
		}
		// 账目守恒
		if rep.ChunksClean+rep.ChunksRepaired+rep.ChunksRebuilt+int64(len(rep.ChunksLost)) != rep.ChunksTotal {
			t.Fatalf("accounting broken: %+v", rep)
		}
		// 直接读：丢失块报错，幸存块完好
		r, err := secvault.Open(f2, testutil.TestKey)
		if err != nil {
			t.Fatal(err)
		}
		for _, idx := range []int64{0, 32, 64} {
			if _, err := r.ReadChunkAt(idx, nil); !errors.Is(err, secvault.ErrChunkUnrecoverable) {
				t.Fatalf("chunk %d: got %v", idx, err)
			}
		}
		for _, idx := range []int64{65, 100, 129} {
			got, err := r.ReadChunkAt(idx, nil)
			if err != nil {
				t.Fatalf("chunk %d: %v", idx, err)
			}
			start := idx * layout.ChunkPlainSize
			end := min(int64(len(plain)), start+layout.ChunkPlainSize)
			if !testutil.BytesEqual(got, plain[start:end]) {
				t.Fatalf("chunk %d mismatch", idx)
			}
		}
	})
}

// TestRandomizedCorruption 随机损坏矩阵（确定性种子）。
func TestRandomizedCorruption(t *testing.T) {
	for seed := int64(1); seed <= 12; seed++ {
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			chunks := 1 + rng.Intn(3)
			tail := rng.Intn(layout.ChunkPlainSize)
			plain := testutil.MakePlain(chunks*layout.ChunkPlainSize+tail, 1000+seed)
			master := testutil.WriteVault(t, plain)

			k := []int{0, 1, 25, 100, 128}[rng.Intn(5)]
			mf := testutil.NewMemFile()
			mf.Write(master.Bytes())
			for j := 0; j < k; j++ {
				chunk := int64(rng.Intn(chunks))
				slot := int64(rng.Intn(layout.ShardsPerBlob))
				testutil.CorruptSlot(t, mf, chunk, slot, rng.Intn(layout.ShardSize))
			}
			r, err := secvault.Open(mf, testutil.TestKey)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			testutil.AssertPlain(t, r, plain)
		})
	}
	// 特例：中间块 130 个坏槽 → 文件级救援
	t.Run("seed-special-overcapacity", func(t *testing.T) {
		plain := testutil.MakePlain(3*layout.ChunkPlainSize+7, 2000)
		master := testutil.WriteVault(t, plain)
		mf := testutil.NewMemFile()
		mf.Write(master.Bytes())
		for i := int64(0); i < 130; i++ {
			testutil.CorruptSlot(t, mf, 1, i, int(i*17%layout.ShardSize))
		}
		r, err := secvault.Open(mf, testutil.TestKey)
		if err != nil {
			t.Fatal(err)
		}
		testutil.AssertPlain(t, r, plain)
	})
}
