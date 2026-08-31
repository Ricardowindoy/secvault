package bench

import (
	"fmt"
	"testing"

	"github.com/klauspost/reedsolomon"

	"secvault"
	"secvault/internal/crypto"
	"secvault/internal/layout"
	"secvault/internal/testutil"
)

// BenchmarkEncode 稳态编码吞吐：整组 128 块写入（含块内 RS + 文件级 parity 全流程）。
func BenchmarkEncode(b *testing.B) {
	const group = 128
	plain := testutil.MakePlain(group*layout.ChunkPlainSize, 1)
	b.SetBytes(group * layout.ChunkPlainSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mf := testutil.NewMemFile()
		w, err := secvault.NewWriter(mf, testutil.TestKey)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := w.Write(plain); err != nil {
			b.Fatal(err)
		}
		if err := w.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkReadChunk 冷读单块（64 块轮换规避缓存）：tag 验证 + GCM 解码。
func BenchmarkReadChunk(b *testing.B) {
	const chunks = 64
	plain := testutil.MakePlain(chunks*layout.ChunkPlainSize, 2)
	mf := writeVaultB(b, plain)
	r, err := secvault.Open(mf, testutil.TestKey)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(layout.ChunkPlainSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.ReadChunkAt(int64(i%chunks), nil); err != nil {
			b.Fatal(err)
		}
	}
}

func writeVaultB(b *testing.B, plain []byte) *testutil.MemFile {
	mf := testutil.NewMemFile()
	w, err := secvault.NewWriter(mf, testutil.TestKey)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		b.Fatal(err)
	}
	if err := w.Close(); err != nil {
		b.Fatal(err)
	}
	return mf
}

// 组件级定位：RS 编码 / GCM / tag 各自的耗时。
func BenchmarkIntraEncode(b *testing.B) {
	rs, err := reedsolomon.New(layout.DataShards, layout.ParityShards)
	if err != nil {
		b.Fatal(err)
	}
	shards := make([][]byte, layout.ShardsPerBlob)
	for i := range shards {
		shards[i] = make([]byte, layout.ShardSize)
	}
	b.SetBytes(layout.BlobPlainSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := rs.Encode(shards); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGCMSeal1MB(b *testing.B) {
	aead, _ := crypto.NewGCM(crypto.DeriveKey(testutil.TestKey, make([]byte, 16), "x"))
	pt := make([]byte, layout.ChunkPlainSize)
	hdr := make([]byte, layout.HeaderSize)
	nonce := make([]byte, layout.NonceSize)
	b.SetBytes(layout.ChunkPlainSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = aead.Seal(nil, nonce, pt, hdr)
	}
}

func BenchmarkFileCodec128(b *testing.B) {
	rs, err := reedsolomon.New(128, layout.FileParityShards)
	if err != nil {
		b.Fatal(err)
	}
	const win = 32
	shards := make([][]byte, 128+layout.FileParityShards)
	for i := range shards {
		shards[i] = make([]byte, win*layout.ShardSize)
	}
	b.SetBytes(128 * win * layout.ShardSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := rs.Encode(shards); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEncodeWorkers worker/inflight 参数扫描（调默认值用）。
func BenchmarkEncodeWorkers(b *testing.B) {
	const group = 128
	plain := testutil.MakePlain(group*layout.ChunkPlainSize, 1)
	b.SetBytes(group * layout.ChunkPlainSize)
	for _, cfg := range []struct{ w, f int }{{2, 8}, {4, 16}, {6, 24}, {8, 32}} {
		b.Run(fmt.Sprintf("w%d-f%d", cfg.w, cfg.f), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				mf := testutil.NewMemFile()
				w, err := secvault.NewWriter(mf, testutil.TestKey, secvault.WithWorkers(cfg.w), secvault.WithInflight(cfg.f))
				if err != nil {
					b.Fatal(err)
				}
				if _, err := w.Write(plain); err != nil {
					b.Fatal(err)
				}
				if err := w.Close(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
