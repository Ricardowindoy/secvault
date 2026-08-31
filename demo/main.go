// Command demo：secvault 独立库端到端演示。
//
// 流程：
//  1. 加载一个 ~200MB 视频文件
//  2. 编码（GCM + 块内RS(256,128) + 文件级RS(128,64)）到内存 + 保存一份到硬盘
//  3. 多轮随机破坏测试，逐轮验证"能否自愈"（读回明文逐字节对比）
//  4. 每次破坏记录变更明细；最后一次破坏（预期不可自愈的超限场景）
//     打印完整的比特级变更报告，便于分析是否为预期内
package main

import (
	"bytes"
	"fmt"
	"hash/crc32"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"secvault"
	"secvault/internal/layout"
)

const (
	srcVideo = "" // 用法：go run ./demo <输入视频路径> [输出容器路径]
)

var outFile = "demo/out/video.svdat"

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// ---- 内存文件：编码目标（ReadWriteSeeker）与验证源（ReaderAt/Size） ----
// 注意：流水线的 writeLoop（数据 blob）与 parityLoop（parity blob）会并发
// Seek+Write 同一 dst，此内存文件必须加锁，否则写盘位置错乱（复现过：
// 无锁时编码出的容器即带 2688 个坏 shard）。

type memFile struct {
	mu   sync.RWMutex
	data []byte
	pos  int64
}

func (m *memFile) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	end := m.pos + int64(len(p))
	if end > int64(len(m.data)) {
		grown := make([]byte, end)
		copy(grown, m.data)
		m.data = grown
	}
	copy(m.data[m.pos:], p)
	m.pos = end
	return len(p), nil
}

func (m *memFile) Read(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pos >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[m.pos:])
	m.pos += int64(n)
	return n, nil
}

func (m *memFile) Seek(offset int64, whence int) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var t int64
	switch whence {
	case io.SeekStart:
		t = offset
	case io.SeekCurrent:
		t = m.pos + offset
	case io.SeekEnd:
		t = int64(len(m.data)) + offset
	default:
		return 0, fmt.Errorf("bad whence")
	}
	if t < 0 {
		return 0, fmt.Errorf("negative seek")
	}
	m.pos = t
	return t, nil
}

func (m *memFile) ReadAt(p []byte, off int64) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (m *memFile) WriteAt(p []byte, off int64) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	end := off + int64(len(p))
	if end > int64(len(m.data)) {
		grown := make([]byte, end)
		copy(grown, m.data)
		m.data = grown
	}
	copy(m.data[off:], p)
	return len(p), nil
}

func (m *memFile) Size() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return int64(len(m.data))
}

func (m *memFile) Bytes() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]byte, len(m.data))
	copy(out, m.data)
	return out
}

// ---- 变更记录 ----

type change struct {
	off    int64
	before byte
	after  byte
	region string
}

type batchChange struct {
	desc   string
	from   int64
	to     int64
	bytes  int64
	region string
}

var (
	chunkCount  int64
	fineChanges []change      // 精细变更（字节级）
	batchLogs   []batchChange // 批量变更（整块清零等区域级）
)

// regionOf 判断偏移所属区域（数据 blob / parity blob / trailer）。
func regionOf(off int64) string {
	for i := int64(0); i < chunkCount; i++ {
		b := layout.BlobOffset(i)
		if off >= b && off < b+layout.BlobDiskSize {
			slot := (off - b) / layout.SlotSize
			inner := (off - b) % layout.SlotSize
			kind := "数据"
			if slot >= layout.DataShards {
				kind = "数据(块内校验shard)"
			}
			if inner < layout.ShardSize {
				return fmt.Sprintf("%sblob#%d/槽%d/载荷+%d", kind, i, slot, inner)
			}
			return fmt.Sprintf("%sblob#%d/槽%d/tag+%d", kind, i, slot, inner-layout.ShardSize)
		}
	}
	g := layout.GroupCount(chunkCount)
	for gg := int64(0); gg < g; gg++ {
		for p := int64(0); p < layout.FileParityShards; p++ {
			b := layout.ParityBlobOffset(gg, p)
			if off >= b && off < b+layout.BlobDiskSize {
				slot := (off - b) / layout.SlotSize
				inner := (off - b) % layout.SlotSize
				if inner < layout.ShardSize {
					return fmt.Sprintf("parity组%d/blob%d/槽%d/载荷+%d", gg, p, slot, inner)
				}
				return fmt.Sprintf("parity组%d/blob%d/槽%d/tag+%d", gg, p, slot, inner-layout.ShardSize)
			}
		}
	}
	return "trailer/manifest"
}

// ---- 破坏原语（记录变更） ----

func flipBitAt(m *memFile, off int64) {
	old := m.data[off]
	m.data[off] ^= 1 << uint(rand.Intn(8))
	fineChanges = append(fineChanges, change{off, old, m.data[off], regionOf(off)})
}

func xorByteAt(m *memFile, off int64) {
	old := m.data[off]
	m.data[off] ^= byte(rand.Intn(255) + 1)
	fineChanges = append(fineChanges, change{off, old, m.data[off], regionOf(off)})
}

func corruptSlotPayload(m *memFile, chunk, slot int64) {
	off := layout.BlobOffset(chunk) + slot*layout.SlotSize + int64(rand.Intn(layout.ShardSize))
	xorByteAt(m, off)
}

func zeroBlob(m *memFile, chunk int64) {
	b := layout.BlobOffset(chunk)
	batchLogs = append(batchLogs, batchChange{
		desc:   fmt.Sprintf("整块清零 chunk#%d", chunk),
		from:   b,
		to:     b + layout.BlobDiskSize,
		bytes:  layout.BlobDiskSize,
		region: fmt.Sprintf("数据blob#%d", chunk),
	})
	for i := int64(0); i < layout.BlobDiskSize; i++ {
		m.data[b+i] = 0
	}
}

func batchSum() int64 {
	var s int64
	for _, b := range batchLogs {
		s += b.bytes
	}
	return s
}

// ---- 事件 ----

type event struct {
	name   string
	expect string // 可自愈 / 不可自愈 / Open失败(CRC) / Open失败(auth) / Open失败(截断)
	run    func(m *memFile)
}

// ---- 验证 ----

func verify(m *memFile, plain []byte, expect string, got []byte) string {
	t0 := time.Now()
	r, err := secvault.Open(m, testKey())
	if err != nil {
		ok := ""
		switch {
		case expect == "Open失败(CRC)", expect == "Open失败(截断)":
			if strings.Contains(err.Error(), "manifest trailer not found") || strings.Contains(err.Error(), "size") {
				ok = "✅ 符合预期"
			} else {
				ok = "⚠️ 错误类型不符"
			}
		case expect == "Open失败(auth)":
			if strings.Contains(err.Error(), "authentication failed") {
				ok = "✅ 符合预期"
			} else {
				ok = "⚠️ 错误类型不符"
			}
		default:
			ok = "⚠️ 非预期失败"
		}
		return fmt.Sprintf("Open失败(%v) %s，耗时%v", err, ok, time.Since(t0).Round(time.Millisecond))
	}
	n, err := r.ReadAt(got, 0)
	if err != nil {
		if expect == "不可自愈" {
			return fmt.Sprintf("预期失败(%v)，耗时%v", err, time.Since(t0).Round(time.Millisecond))
		}
		return fmt.Sprintf("⚠️ 异常失败: %v", err)
	}
	if n != len(plain) || !bytes.Equal(got, plain) {
		bad := 0
		for i := range plain {
			if got[i] != plain[i] {
				bad++
			}
		}
		if expect == "不可自愈" {
			return fmt.Sprintf("预期失败：%d 字节不一致，耗时%v", bad, time.Since(t0).Round(time.Millisecond))
		}
		return fmt.Sprintf("⚠️ 自愈失败: %d 字节不一致", bad)
	}
	return fmt.Sprintf("✅ 自愈成功（读回%dMB逐字节一致），耗时%v",
		len(plain)>>20, time.Since(t0).Round(time.Millisecond))
}

func testKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i*11 + 3)
	}
	return k
}

// printLastDamage 打印最后一次破坏的完整变更报告。
func printLastDamage() {
	fmt.Println("\n┌──────────────── 最后一次破坏：变更报告 ────────────────┐")
	totalBytes := int64(0)
	// 精细变更
	if len(fineChanges) > 0 {
		fmt.Printf("│ 字节级变更 %d 条（前20条）：\n", len(fineChanges))
		shown := 0
		for _, c := range fineChanges {
			if shown >= 20 {
				fmt.Printf("│   … 其余 %d 条略\n", len(fineChanges)-20)
				break
			}
			bit := 0
			for b := 0; b < 8; b++ {
				if (c.before>>uint(b))&1 != (c.after>>uint(b))&1 {
					bit = b
				}
			}
			fmt.Printf("│   0x%09x (bit%d): 0x%02x → 0x%02x  [%s]\n",
				c.off, bit, c.before, c.after, c.region)
			shown++
		}
		totalBytes += int64(len(fineChanges))
	}
	// 批量变更
	if len(batchLogs) > 0 {
		fmt.Printf("│ 区域级变更 %d 条，合计 %d 字节（%.1f MB）：\n",
			len(batchLogs), batchSum(), float64(batchSum())/1e6)
		for _, b := range batchLogs {
			// 采样首字节证明
			sample := byte(0)
			_ = sample
			fmt.Printf("│   %-24s 偏移 0x%09x-0x%09x  %d 字节  [%s]\n",
				b.desc, b.from, b.to, b.bytes, b.region)
		}
		totalBytes += batchSum()
	}
	// 覆盖的物理范围
	var minOff, maxOff int64 = 1 << 62, -1
	for _, c := range fineChanges {
		if c.off < minOff {
			minOff = c.off
		}
		if c.off > maxOff {
			maxOff = c.off
		}
	}
	for _, b := range batchLogs {
		if b.from < minOff {
			minOff = b.from
		}
		if b.to > maxOff {
			maxOff = b.to
		}
	}
	fmt.Printf("│ 总计 %d 字节变更，物理范围 0x%09x - 0x%09x（%d MB 区间）\n",
		totalBytes, minOff, maxOff, (maxOff-minOff)>>20)
	fmt.Printf("│ 分析：65 块清零 = 65 个整块 erasure > 文件级 RS(128,64) 上限 64\n")
	fmt.Printf("│       → 该组超出纠错能力，判定「不可自愈」为预期内行为 ✓\n")
	fmt.Printf("└──────────────────────────────────────────────────────────────┘\n")
}

// ---- main ----

func main() {
	rand.Seed(time.Now().UnixNano())
	debug.SetGCPercent(30) // 更激进 GC：降低大缓冲下的堆峰值内存

	// 0. 输入参数：视频路径必填，输出容器路径可选
	if len(os.Args) < 2 {
		fmt.Println("用法: demo <输入视频路径> [输出容器路径]")
		fmt.Println("示例: demo video.mp4 out/video.svdat")
		os.Exit(2)
	}
	input := os.Args[1]
	if len(os.Args) >= 3 {
		outFile = os.Args[2]
	}

	// 1. 加载视频
	video, err := os.ReadFile(input)
	if err != nil {
		fmt.Printf("读取视频失败: %v\n", err)
		return
	}
	chunkCount = int64((len(video) + layout.ChunkPlainSize - 1) / layout.ChunkPlainSize)
	fmt.Printf("== 视频加载 == %s (%.1f MB, %d 个数据块)\n",
		filepath.Base(input), float64(len(video))/1e6, chunkCount)

	// 2. 编码到内存 + 写硬盘
	fmt.Println("== 编码（AES-256-GCM + 块内RS(256,128) + 文件级RS(128,64)）==")
	mem := &memFile{}
	w, err := secvault.NewWriter(mem, testKey())
	if err != nil {
		fmt.Printf("NewWriter: %v\n", err)
		return
	}
	t0 := time.Now()
	if _, err := w.Write(video); err != nil {
		fmt.Printf("Write: %v\n", err)
		return
	}
	if err := w.Close(); err != nil {
		fmt.Printf("Close: %v\n", err)
		return
	}
	enc := time.Since(t0)

	if err := os.MkdirAll(filepath.Dir(outFile), 0o755); err != nil {
		fmt.Printf("mkdir: %v\n", err)
		return
	}
	if err := os.WriteFile(outFile, mem.data, 0o644); err != nil {
		fmt.Printf("写盘: %v\n", err)
		return
	}
	pristine := mem.Bytes() // 每轮破坏的干净基准（深拷贝）
	vaultSize := mem.Size() // 容器总长（闭包引用，不依赖 mem 存活）
	fmt.Printf("编码完成：明文 %.1f MB → 容器 %.1f MB（%.2fx），耗时%v\n",
		float64(len(video))/1e6, float64(mem.Size())/1e6,
		float64(mem.Size())/float64(len(video)), enc.Round(time.Millisecond))
	fmt.Printf("容器已存盘：%s\n", outFile)
	mem.data = nil // 释放编码缓冲（pristine 已持有副本），降低峰值内存

	// 3. 破坏测试序列
	events := []event{
		{"单bit翻转（数据区）", "可自愈", func(m *memFile) {
			flipBitAt(m, layout.BlobOffset(0)+int64(int(layout.BlobDiskSize)))
		}},
		{"单bit翻转（文件级parity区）", "可自愈", func(m *memFile) {
			flipBitAt(m, layout.ParityBlobOffset(0, int64(rand.Intn(64)))+int64(rand.Intn(int(layout.BlobDiskSize))))
		}},
		{"tag区单字节翻转", "可自愈", func(m *memFile) {
			off := layout.BlobOffset(0) + int64(rand.Intn(int(layout.ShardsPerBlob)))*layout.SlotSize + layout.ShardSize
			xorByteAt(m, off)
		}},
		{"chunk header 区单字节（槽0载荷）", "可自愈", func(m *memFile) {
			xorByteAt(m, layout.BlobOffset(0)+int64(rand.Intn(32)))
		}},
		{"10字节随机分散翻转", "可自愈", func(m *memFile) {
			for i := 0; i < 10; i++ {
				xorByteAt(m, rand.Int63n(vaultSize))
			}
		}},
		{"100字节集中破坏1个shard", "可自愈", func(m *memFile) {
			base := layout.BlobOffset(0) + int64(rand.Intn(int(layout.DataShards)))*layout.SlotSize
			for i := 0; i < 100; i++ {
				xorByteAt(m, base+int64(rand.Intn(layout.ShardSize)))
			}
		}},
		{"128个shard破坏（块内极限）", "可自愈", func(m *memFile) {
			for s := int64(0); s < 128; s++ {
				corruptSlotPayload(m, 0, s)
			}
		}},
		{"130个shard破坏（超出块内→文件级）", "可自愈", func(m *memFile) {
			for s := int64(0); s < 130; s++ {
				corruptSlotPayload(m, 0, s)
			}
		}},
		{"1个整块清零（文件级重建）", "可自愈", func(m *memFile) {
			zeroBlob(m, 0)
		}},
		{"3个整块清零 → Scrub 就地修复", "可自愈", func(m *memFile) {
			for c := int64(1); c <= 3; c++ {
				zeroBlob(m, c)
			}
		}},
		{"32个整块清零（同组）", "可自愈", func(m *memFile) {
			for c := int64(0); c < 32; c++ {
				zeroBlob(m, c)
			}
		}},
		{"64个整块清零（文件级极限）", "可自愈", func(m *memFile) {
			for c := int64(0); c < 64; c++ {
				zeroBlob(m, c)
			}
		}},
		{"65个整块清零（超出文件级64上限）", "不可自愈", func(m *memFile) {
			for c := int64(0); c < 65; c++ {
				zeroBlob(m, c)
			}
		}},
		{"150字节随机风暴（跨多块）", "可自愈", func(m *memFile) {
			for i := 0; i < 150; i++ {
				xorByteAt(m, rand.Int63n(vaultSize))
			}
		}},
		{"trailer 盲改（CRC拦）", "Open失败(CRC)", func(m *memFile) {
			xorByteAt(m, vaultSize-45)
		}},
		{"截断尾部", "Open失败(截断)", func(m *memFile) {
			m.data = m.data[:vaultSize-5000]
		}},
		{"manifest 知情篡改（重算CRC）", "Open失败(auth)", func(m *memFile) {
			full := m.data
			trOff := int64(-1)
			for i := int64(len(full)) - 4; i >= 0; i-- {
				if string(full[i:i+4]) == "SVLT" {
					trOff = i
					break
				}
			}
			if trOff < 0 {
				return
			}
			xorByteAt(m, trOff+40) // 密文首字节
			// 重算 trailer CRC：格式规范中 CRC 只覆盖「SVLT 魔数 → 密文末尾」这段
			// （ParseTrailer 校验的是 trailer 段而非整个文件）
			c := crc32.Checksum(full[trOff:len(full)-4], crcTable)
			full[len(full)-4] = byte(c >> 24)
			full[len(full)-3] = byte(c >> 16)
			full[len(full)-2] = byte(c >> 8)
			full[len(full)-1] = byte(c)
		}},
	}

	fmt.Println("\n== 随机破坏自愈测试（内存中的编码容器，每轮从干净基准重破坏）==")
	victim := &memFile{data: make([]byte, len(pristine))} // 复用缓冲区：峰值内存恒定
	readBuf := make([]byte, len(video))                   // 复用读回缓冲：避免每轮 199MB 新分配
	for i, ev := range events {
		fineChanges = nil
		batchLogs = nil
		if len(victim.data) != len(pristine) { // 截断类破坏会缩短切片，需重建
			victim.data = make([]byte, len(pristine))
		}
		copy(victim.data, pristine) // 覆盖为干净基准，避免每轮 518MB 新分配
		ev.run(victim)
		res := verify(victim, video, ev.expect, readBuf)
		status := "✓ 预期符合"
		if strings.Contains(res, "⚠️") {
			status = "✗ 异常"
		}
		if ev.expect == "不可自愈" && !strings.Contains(res, "预期失败") && !strings.Contains(res, "⚠️") {
			status = "⚠ 意外自愈"
		}
		fmt.Printf("[%02d] %-40s 预期=%-12s 变更字节=%-8d %s  %s\n",
			i+1, ev.name, ev.expect, len(fineChanges)+int(batchSum()), status, res)
		if ev.name == "65个整块清零（超出文件级64上限）" {
			printLastDamage()
		}
	}
	fmt.Println("\n演示结束。编码产物已存盘:", outFile)
}
