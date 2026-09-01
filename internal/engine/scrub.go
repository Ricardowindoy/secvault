package engine

import (
	"bytes"
	"io"
	"sort"

	ierrors "secvault/internal/errors"
	"secvault/internal/crypto"
	"secvault/internal/layout"
)

// ScrubStats 巡检统计（门面层包装成公共 Report）。
type ScrubStats struct {
	ChunksTotal       int64
	ChunksClean       int64
	ChunksRepaired    int64
	ChunksRebuilt     int64
	ChunksLost        []int64
	ShardsBad         int64
	ShardsRepaired    int64
	ParitySlotsBad    int64
	ParityShardsFixed int64
}

// Scrub 三遍巡检编排：pass1 逐块 tag+块内修复+GCM 终审（回写坏槽）；
// pass2 文件级整块重建（按组聚合，回写整 blob）；pass3 可选 parity 重算。
// w 为 nil 时纯只读校验；修复来源是纠错冗余本身。
func (c *Container) Scrub(w writeAt, rebuildParity bool) (*ScrubStats, error) {
	rep := &ScrubStats{ChunksTotal: c.Man.ChunkCount}
	var needFile []int64

	// pass1：逐块 tag 验证 + 块内修复 + GCM 深度校验
	for idx := int64(0); idx < c.Man.ChunkCount; idx++ {
		payloads, _, bad, err := c.GatherBlob(idx)
		if err != nil {
			return nil, err
		}
		rep.ShardsBad += int64(len(bad))
		if len(bad) > layout.ParityShards {
			needFile = append(needFile, idx)
			continue
		}
		repaired := false
		if len(bad) > 0 {
			fixed, ok := c.RepairIntra(payloads, bad)
			if !ok {
				needFile = append(needFile, idx)
				continue
			}
			payloads = fixed
			repaired = true
		}
		if _, derr := c.DecodeChunk(idx, payloads); derr != nil {
			rep.ChunksLost = append(rep.ChunksLost, idx)
			continue
		}
		if repaired {
			rep.ChunksRepaired++
			rep.ShardsRepaired += int64(len(bad))
			if w != nil {
				for _, i := range bad {
					slot := make([]byte, layout.SlotSize)
					copy(slot, payloads[i])
					copy(slot[layout.ShardSize:], crypto.ShardTag(payloads[i]))
					if _, err := w.WriteAt(slot, c.spec.DataBlobOffset(idx)+int64(i)*layout.SlotSize); err != nil {
						return nil, err
					}
				}
			}
		} else {
			rep.ChunksClean++
		}
	}

	// pass2：文件级整块重建（按组聚合，一次扫窗重建组内全部缺失块）
	lostSet := map[int64]bool{}
	byGroup := map[int64][]int64{}
	for _, idx := range needFile {
		g := idx / layout.FileGroupChunks
		byGroup[g] = append(byGroup[g], idx%layout.FileGroupChunks)
	}
	groups := make([]int64, 0, len(byGroup))
	for g := range byGroup {
		groups = append(groups, g)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i] < groups[j] })
	for _, g := range groups {
		positions := byGroup[g]
		sort.Slice(positions, func(i, j int) bool { return positions[i] < positions[j] })
		m, ok := c.RebuildMissing(g, positions)
		if !ok {
			for _, pos := range positions {
				idx := g*layout.FileGroupChunks + pos
				rep.ChunksLost = append(rep.ChunksLost, idx)
				lostSet[idx] = true
			}
			continue
		}
		for _, pos := range positions {
			idx := g*layout.FileGroupChunks + pos
			payloads := m[pos]
			if _, derr := c.DecodeChunk(idx, payloads); derr != nil {
				rep.ChunksLost = append(rep.ChunksLost, idx)
				lostSet[idx] = true
				continue
			}
			rep.ChunksRebuilt++
			if w != nil {
				disk := make([]byte, 0, layout.BlobDiskSize)
				for i := 0; i < layout.ShardsPerBlob; i++ {
					disk = append(disk, payloads[i]...)
					disk = append(disk, crypto.ShardTag(payloads[i])...)
				}
				if _, err := w.WriteAt(disk, c.spec.DataBlobOffset(idx)); err != nil {
					return nil, err
				}
			}
		}
	}

	// pass3：文件级 parity 重算与修复（跳过含丢失块的组）
	if rebuildParity {
		if err := c.rebuildFileParity(w, rep, lostSet); err != nil {
			return nil, err
		}
	}
	return rep, nil
}

// ScrubGCMOnly gcm-only 容器巡检：整文件 = 1 个"块"（复用 ChunksTotal/Lost 语义）。
// GCM.Open 失败 → 损坏标记（ChunksLost=[0]）；本类别无冗余可修，不回写——
// Scrub 与 Verify 语义相同，损坏交调用方重拉。I/O 错误显式传播。
func (c *Container) ScrubGCMOnly() (*ScrubStats, error) {
	rep := &ScrubStats{ChunksTotal: 1}
	if _, err := c.LoadGCMOnly(); err != nil {
		if ierrors.Is(err, ierrors.ErrGCMOnlyCorrupted) {
			rep.ChunksLost = append(rep.ChunksLost, 0)
			return rep, nil
		}
		return nil, err
	}
	rep.ChunksClean = 1
	return rep, nil
}

// ScrubStrong rs-strong 容器巡检（DESIGN-v3-phase2 §2.9/§3.5）：逐槽 tag 验证 →
// 坏槽 RS(32,64) 重建 → GCM 终审 → 回写坏槽（载荷 + 重算 tag）。w 为 nil 时纯只读
// 校验（*Repaired 表示"可修复"），与 rs-dual 的 Verify/Scrub 语义一致。
// 重建后 GCM 终审失败（tag 一致但内容损坏，RS 只保证数学一致）→ ChunksLost=[0]；
// 坏槽 >64（超出 RS(32,64) 容错边界）→ 同样 ChunksLost=[0]，不回写。
// RebuildParity 对 rs-strong 无意义（单 blob 无文件级 parity），忽略。
func (c *Container) ScrubStrong(w writeAt) (*ScrubStats, error) {
	rep := &ScrubStats{ChunksTotal: 1}
	shards, bad, shardSize, err := c.gatherStrongSlots()
	if err != nil {
		return nil, err
	}
	rep.ShardsBad = int64(len(bad))
	fixed := shards
	if len(bad) > 0 {
		rebuilt, ok := c.reconstructStrong(shards, bad)
		if !ok {
			rep.ChunksLost = append(rep.ChunksLost, 0)
			return rep, nil
		}
		fixed = rebuilt
	}
	if _, derr := c.decodeStrongArea(fixed, shardSize); derr != nil {
		rep.ChunksLost = append(rep.ChunksLost, 0)
		return rep, nil
	}
	if len(bad) > 0 {
		rep.ChunksRepaired = 1
		rep.ShardsRepaired = int64(len(bad))
		if w != nil {
			slotSize := shardSize + int64(layout.TagSize)
			for _, i := range bad {
				slot := make([]byte, slotSize)
				copy(slot, fixed[i])
				copy(slot[shardSize:], crypto.ShardTag(fixed[i]))
				if _, err := w.WriteAt(slot, int64(i)*slotSize); err != nil {
					return nil, err
				}
			}
		}
	} else {
		rep.ChunksClean = 1
	}
	return rep, nil
}

// writeAt 最小写入接口（门面层把 io.WriterAt 传进来）。
type writeAt interface {
	WriteAt(p []byte, off int64) (int, error)
}

// rebuildFileParity 重算文件级 parity 并修复坏槽（含丢失块的组跳过）。
func (c *Container) rebuildFileParity(w writeAt, rep *ScrubStats, lostSet map[int64]bool) error {
	const win = 32
	raw := make([]byte, win*layout.SlotSize)

	for g := int64(0); g < c.Groups; g++ {
		kData := int(c.DataChunks(g))
		// 组内有丢失块 → 数据不完整，跳过（parity 保持现状）
		skip := false
		for pos := int64(0); pos < int64(kData) && !skip; pos++ {
			if lostSet[g*layout.FileGroupChunks+pos] {
				skip = true
			}
		}
		if skip {
			continue
		}
		m := int(c.spec.GroupParity(g, c.Man.ChunkCount)) // v2 恒 64
		shards := make([][]byte, 0, layout.FileGroupChunks+m)
		rs, err := c.codecs.File(kData, m)
		if err != nil {
			return err
		}
		for j0 := 0; j0 < layout.ShardsPerBlob; j0 += win {
			wc := win
			if j0+win > layout.ShardsPerBlob {
				wc = layout.ShardsPerBlob - j0
			}
			shards = shards[:0]
			for i := 0; i < kData; i++ {
				p, ok, err := readWindow(c.src, c.spec.DataBlobOffset(g*layout.FileGroupChunks+int64(i))+int64(j0)*layout.SlotSize, wc)
				if err != nil {
					return err // 读错误显式传播（原语义）
				}
				if !ok {
					// pass1 之后数据列不应再坏；保守中止
					return nil
				}
				shards = append(shards, p)
			}
			for p := 0; p < m; p++ {
				shards = append(shards, make([]byte, wc*layout.ShardSize))
			}
			if err := rs.Encode(shards); err != nil {
				return err
			}
			for p := 0; p < m; p++ {
				off := c.spec.ParityBlobOffset(g, c.DataChunks(g), int64(p)) + int64(j0)*layout.SlotSize
				if _, err := c.src.ReadAt(raw[:wc*layout.SlotSize], off); err != nil && err != io.EOF {
					return err
				}
				for cIdx := 0; cIdx < wc; cIdx++ {
					existing := raw[cIdx*layout.SlotSize : (cIdx+1)*layout.SlotSize]
					newCol := shards[kData+p][cIdx*layout.ShardSize : (cIdx+1)*layout.ShardSize]
					if !crypto.VerifyTag(existing[:layout.ShardSize], existing[layout.ShardSize:]) ||
						!bytes.Equal(existing[:layout.ShardSize], newCol) {
						rep.ParitySlotsBad++
						if w != nil {
							slot := make([]byte, layout.SlotSize)
							copy(slot, newCol)
							copy(slot[layout.ShardSize:], crypto.ShardTag(newCol))
							if _, err := w.WriteAt(slot, off+int64(cIdx)*layout.SlotSize); err != nil {
								return err
							}
							rep.ParityShardsFixed++
						}
					}
				}
			}
		}
	}
	return nil
}
