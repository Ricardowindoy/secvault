package bench

import (
	"encoding/binary"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/klauspost/reedsolomon"

	"secvault/internal/codec"
	"secvault/internal/crypto"
	"secvault/internal/format"
	"secvault/internal/layout"
	"secvault/internal/testutil"
)

// TestStageProfile 分阶段耗时剖析（testutil.MemFile 隔离磁盘；-short 跳过）。
// 逻辑与 Writer.emitChunk/writeGroupParity 等价，仅插入计时。
func TestStageProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("profile test")
	}
	const chunks = 128
	fileID := make([]byte, 16)
	aead, _ := crypto.NewGCM(crypto.DeriveKey(testutil.TestKey, fileID, "secvault/chunk/v1"))
	intra, _ := reedsolomon.New(layout.DataShards, layout.ParityShards)
	fileCodec, _ := reedsolomon.New(layout.FileGroupChunks, layout.FileParityShards)
	plain := testutil.MakePlain(layout.ChunkPlainSize, 5)

	var tGCM, tAsm, tIntra, tTag, tSlot, tReadback, tFileEnc, tFileWrite time.Duration
	dst := testutil.NewMemFile()
	writePos := int64(0)
	slotBuf := make([]byte, 0, layout.SlotSize)
	shards := make([][]byte, layout.ShardsPerBlob)
	par := make([][]byte, layout.FileParityShards)
	raw := make([]byte, 32*layout.SlotSize)
	const win = 32

	blobAsm := func(hdr, ct []byte) {
		blob := make([]byte, layout.BlobPlainSize)
		copy(blob, hdr)
		copy(blob[len(hdr):], ct)
		for i := 0; i < layout.DataShards; i++ {
			shards[i] = blob[i*layout.ShardSize : (i+1)*layout.ShardSize]
		}
		for i := layout.DataShards; i < layout.ShardsPerBlob; i++ {
			shards[i] = make([]byte, layout.ShardSize)
		}
	}

	for c := 0; c < chunks; c++ {
		nonce := make([]byte, layout.NonceSize)
		binary.BigEndian.PutUint64(nonce[4:], uint64(c))
		hdr := (&format.ChunkHeader{Index: int64(c), PlainLen: layout.ChunkPlainSize, Nonce: nonce}).Marshal()

		t0 := time.Now()
		ct := aead.Seal(nil, nonce, plain, hdr)
		tGCM += time.Since(t0)

		t0 = time.Now()
		blobAsm(hdr, ct)
		tAsm += time.Since(t0)

		t0 = time.Now()
		if err := intra.Encode(shards); err != nil {
			t.Fatal(err)
		}
		tIntra += time.Since(t0)

		t0 = time.Now()
		for i := 0; i < layout.ShardsPerBlob; i++ {
			_ = crypto.ShardTag(shards[i])
		}
		tTag += time.Since(t0)

		t0 = time.Now()
		for i := 0; i < layout.ShardsPerBlob; i++ {
			slotBuf = append(slotBuf[:0], shards[i]...)
			slotBuf = append(slotBuf, crypto.ShardTag(shards[i])...)
			dst.Seek(writePos, 0)
			dst.Write(slotBuf)
			writePos += int64(len(slotBuf))
		}
		tSlot += time.Since(t0)
	}

	// ---- 组级 parity ----
	groupBase := int64(0)
	parBase := writePos
	for j0 := 0; j0 < layout.ShardsPerBlob; j0 += win {
		wc := win
		if j0+win > layout.ShardsPerBlob {
			wc = layout.ShardsPerBlob - j0
		}
		data := make([][]byte, layout.FileGroupChunks)
		t0 := time.Now()
		for i := 0; i < layout.FileGroupChunks; i++ {
			off := groupBase + int64(i)*layout.BlobDiskSize + int64(j0)*layout.SlotSize
			dst.Seek(off, 0)
			io.ReadFull(dst, raw[:wc*layout.SlotSize])
			data[i] = codec.ExtractPayloads(raw[:wc*layout.SlotSize], wc)
		}
		tReadback += time.Since(t0)

		t0 = time.Now()
		for p := range par {
			par[p] = make([]byte, wc*layout.ShardSize)
		}
		all := append(append([][]byte{}, data...), par...)
		if err := fileCodec.Encode(all); err != nil {
			t.Fatal(err)
		}
		tFileEnc += time.Since(t0)

		t0 = time.Now()
		for p := 0; p < layout.FileParityShards; p++ {
			slotBuf = slotBuf[:0]
			for c := 0; c < wc; c++ {
				col := par[p][c*layout.ShardSize : (c+1)*layout.ShardSize]
				slotBuf = append(slotBuf, col...)
				slotBuf = append(slotBuf, crypto.ShardTag(col)...)
			}
			off := parBase + int64(p)*layout.BlobDiskSize + int64(j0)*layout.SlotSize
			dst.Seek(off, 0)
			dst.Write(slotBuf)
		}
		tFileWrite += time.Since(t0)
	}

	total := tGCM + tAsm + tIntra + tTag + tSlot + tReadback + tFileEnc + tFileWrite
	dataBytes := int64(chunks) * layout.ChunkPlainSize
	mb := func(d time.Duration) string {
		return fmt.Sprintf("%.1f", float64(dataBytes)/1e6/d.Seconds())
	}
	t.Logf("== 每块(1MB)分阶段 ==   耗时ms   占比%%   MB/s")
	for _, row := range []struct {
		name string
		d    time.Duration
	}{
		{"1.GCM 加密", tGCM},
		{"2.blob 组装+填充", tAsm},
		{"3.块内RS leopard(单线程)", tIntra},
		{"4.shard tag SHA×384", tTag},
		{"5.槽位写(testutil.MemFile)", tSlot},
		{"6.组parity读回(202MB)", tReadback},
		{"7.文件级RS(经典,多核)", tFileEnc},
		{"8.parity写(101MB)", tFileWrite},
	} {
		pct := 100 * float64(row.d) / float64(total)
		t.Logf("%-26s %8.1fms %6.1f%%  %s", row.name, float64(row.d)/1e6/float64(chunks), pct, mb(row.d))
	}
	t.Logf("== 合计 %.2fs / %dMB → %.1f MB/s（testutil.MemFile，无磁盘）==", total.Seconds(), dataBytes/1e6, float64(dataBytes)/1e6/total.Seconds())
}

// TestStageParallel 块级并行实验：单块串行流水 vs 8 块并发（每块内仍串行）。
func TestStageParallel(t *testing.T) {
	if testing.Short() {
		t.Skip("profile test")
	}
	fileID := make([]byte, 16)
	aead, _ := crypto.NewGCM(crypto.DeriveKey(testutil.TestKey, fileID, "secvault/chunk/v1"))
	intra, _ := reedsolomon.New(layout.DataShards, layout.ParityShards)
	plain := testutil.MakePlain(layout.ChunkPlainSize, 6)

	oneChunk := func() {
		nonce := make([]byte, layout.NonceSize)
		hdr := (&format.ChunkHeader{PlainLen: layout.ChunkPlainSize, Nonce: nonce}).Marshal()
		ct := aead.Seal(nil, nonce, plain, hdr)
		blob := make([]byte, layout.BlobPlainSize)
		copy(blob, hdr)
		copy(blob[len(hdr):], ct)
		shards := make([][]byte, layout.ShardsPerBlob)
		for i := 0; i < layout.DataShards; i++ {
			shards[i] = blob[i*layout.ShardSize : (i+1)*layout.ShardSize]
		}
		for i := layout.DataShards; i < layout.ShardsPerBlob; i++ {
			shards[i] = make([]byte, layout.ShardSize)
		}
		if err := intra.Encode(shards); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < layout.ShardsPerBlob; i++ {
			_ = crypto.ShardTag(shards[i])
		}
	}

	// 预热
	oneChunk()

	const n = 8
	t0 := time.Now()
	for i := 0; i < n; i++ {
		oneChunk()
	}
	serial := time.Since(t0)

	t0 = time.Now()
	done := make(chan struct{})
	for g := 0; g < n; g++ {
		go func() {
			oneChunk()
			done <- struct{}{}
		}()
	}
	for g := 0; g < n; g++ {
		<-done
	}
	parallel := time.Since(t0)

	t.Logf("串行 8 块: %v (%.1f ms/块)", serial, float64(serial)/1e6/n)
	t.Logf("并行 8 块: %v (墙钟 %.1f ms/块, 加速 %.2fx)", parallel, float64(parallel)/1e6/n, float64(serial)/float64(parallel))
}

// TestCodecGoroutines 文件级 codec 的 WithMaxGoroutines 效果对照。
func TestCodecGoroutines(t *testing.T) {
	if testing.Short() {
		t.Skip("profile test")
	}
	const win = 32
	mkShards := func() [][]byte {
		shards := make([][]byte, layout.FileGroupChunks+layout.FileParityShards)
		for i := range shards {
			shards[i] = make([]byte, win*layout.ShardSize)
		}
		return shards
	}
	for _, g := range []int{1, 4, 8, 16} {
		rs, err := reedsolomon.New(layout.FileGroupChunks, layout.FileParityShards, reedsolomon.WithMaxGoroutines(g))
		if err != nil {
			t.Fatal(err)
		}
		shards := mkShards()
		start := time.Now()
		for i := 0; i < 6; i++ {
			if err := rs.Encode(shards); err != nil {
				t.Fatal(err)
			}
		}
		d := time.Since(start) / 6
		t.Logf("fileCodec(128,64) goroutines=%-2d  %v/窗口  (%.0f MB/s 数据侧)",
			g, d, float64(layout.FileGroupChunks*win*layout.ShardSize)/1e6/d.Seconds())
	}
	// leopard：goroutines 选项无效（单线程实现）
	lep, _ := reedsolomon.New(layout.DataShards, layout.ParityShards, reedsolomon.WithMaxGoroutines(8))
	shards := make([][]byte, layout.ShardsPerBlob)
	for i := range shards {
		shards[i] = make([]byte, layout.ShardSize)
	}
	start := time.Now()
	for i := 0; i < 10; i++ {
		if err := lep.Encode(shards); err != nil {
			t.Fatal(err)
		}
	}
	d := time.Since(start) / 10
	t.Logf("intra leopard(256,128) goroutines=8(无效)  %v/MB  (%.0f MB/s)", d, float64(layout.BlobPlainSize)/1e6/d.Seconds())
}
