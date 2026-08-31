package secvault

import (
	"fmt"
	"io"

	"secvault/internal/engine"
	ierrors "secvault/internal/errors"
)

// Options scrub 选项。
type Options struct {
	// RebuildParity 重算文件级 parity 并修复坏槽（含组内丢失块的组会被跳过）。
	RebuildParity bool
}

// Report 巡检/校验报告。Verify 语义下 *Repaired/*Rebuilt 表示"可修复/可重建"，
// Scrub 语义下表示"已修复/已重建"。恒有：
// ChunksClean + ChunksRepaired + ChunksRebuilt + len(ChunksLost) == ChunksTotal。
type Report struct {
	ChunksTotal       int64   `json:"chunks_total"`
	ChunksClean       int64   `json:"chunks_clean"`
	ChunksRepaired    int64   `json:"chunks_repaired"`
	ChunksRebuilt     int64   `json:"chunks_rebuilt"`
	ChunksLost        []int64 `json:"chunks_lost,omitempty"`
	ShardsBad         int64   `json:"shards_bad"`
	ShardsRepaired    int64   `json:"shards_repaired"`
	ParitySlotsBad    int64   `json:"parity_slots_bad"`
	ParityShardsFixed int64   `json:"parity_shards_fixed"`
}

type readWriteAt interface {
	io.ReaderAt
	io.WriterAt
}

// Verify 只读深度校验：逐 shard tag + 块内可修复性 + 文件级可重建性 + GCM 终审。
// 不修改文件。
func Verify(src io.ReaderAt, masterKey []byte, opts Options) (*Report, error) {
	c, err := engine.Open(src, masterKey)
	if err != nil {
		return nil, err
	}
	st, err := c.Scrub(nil, opts.RebuildParity)
	if err != nil {
		return nil, err
	}
	return toReport(st), nil
}

// Scrub 深度校验并就地修复：块内修复回写坏槽，块内救不活的整块走文件级
// 重建并整体回写，可选重算文件级 parity。修复来源是纠错冗余本身。
func Scrub(rw readWriteAt, masterKey []byte, opts Options) (*Report, error) {
	c, err := engine.Open(rw, masterKey)
	if err != nil {
		return nil, err
	}
	st, err := c.Scrub(rw, opts.RebuildParity)
	if err != nil {
		return nil, err
	}
	return toReport(st), nil
}

func toReport(st *engine.ScrubStats) *Report {
	return &Report{
		ChunksTotal:       st.ChunksTotal,
		ChunksClean:       st.ChunksClean,
		ChunksRepaired:    st.ChunksRepaired,
		ChunksRebuilt:     st.ChunksRebuilt,
		ChunksLost:        st.ChunksLost,
		ShardsBad:         st.ShardsBad,
		ShardsRepaired:    st.ShardsRepaired,
		ParitySlotsBad:    st.ParitySlotsBad,
		ParityShardsFixed: st.ParityShardsFixed,
	}
}

// ChunkError 携带出错的块序号，errors.Is 可匹配哨兵错误。
type ChunkError struct {
	Index int64
	Err   error
}

func (e *ChunkError) Error() string { return fmt.Sprintf("secvault: chunk %d: %v", e.Index, e.Err) }
func (e *ChunkError) Unwrap() error { return e.Err }

var _ = ierrors.New
