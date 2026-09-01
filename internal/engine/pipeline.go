package engine

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"secvault/internal/codec"
	"secvault/internal/crypto"
	"secvault/internal/format"
	"secvault/internal/layout"
)

// Pipeline 是 v2 无屏障写入流水线的全部状态与编排：
// 主 goroutine 切块 → workers 并行 GCM+RS+拼装 → 落盘 goroutine 按序写数据 blob
// → parity 累加器 goroutine 后台算组级 parity（零读回零拷贝）。
// 门面（顶层 Writer）负责生命周期与 trailer；本结构只管数据面。
type Pipeline struct {
	dst   io.ReadWriteSeeker
	aead  crypto.AEAD
	codec *codec.Cache
	spec  layout.Spec

	noncePfx [4]byte
	workers  int

	encodeCh chan *chunkJob
	outCh    chan *chunkJob
	parCh    chan parityMsg
	wg       sync.WaitGroup
	doneCh   chan struct{} // writeLoop 完成
	parDone  chan struct{} // parityLoop 完成

	errMu sync.Mutex
	err   error

	// 仅生产者（调用方）goroutine 触碰
	chunkIdx  int64
	chunkBuf  []byte
	plainPool sync.Pool

	// 仅落盘 goroutine 触碰；final* 在 doneCh 关闭后由调用方读
	groupChunks int
	groupsDone  int64
	finalKData  int
	finalGroup  int64
	plainSize   int64

	slotBuf []byte

	blobPool sync.Pool
	parPool  sync.Pool
	diskPool sync.Pool
}

type chunkJob struct {
	idx      int64
	plainLen int
	plain    []byte // 生产者填充；worker GCM 后回收
	blob     []byte // worker 产出：256 数据列载荷，移交 parity 累加器
	par      []byte // worker 产出：128 块内校验列载荷，移交 parity 累加器
	disk     []byte // worker 拼装；落盘 goroutine 写后回收
	failed   bool
}

type parityMsg struct {
	flush bool
	g     int64
	kData int
	blob  []byte
	par   []byte
}

// NewPipeline 装配流水线（启动全部 goroutine）。
// 调用方负责在结束时调用 Close 流程（FlushLast → Drain）。
func NewPipeline(dst io.ReadWriteSeeker, aead crypto.AEAD, cd *codec.Cache,
	noncePfx [4]byte, workers, inflight int, spec layout.Spec) *Pipeline {
	p := &Pipeline{
		dst:      dst,
		aead:     aead,
		codec:    cd,
		noncePfx: noncePfx,
		workers:  workers,
		encodeCh: make(chan *chunkJob, inflight/2),
		outCh:    make(chan *chunkJob, inflight-inflight/2),
		parCh:    make(chan parityMsg, 256),
		doneCh:   make(chan struct{}),
		parDone:  make(chan struct{}),
		slotBuf:  make([]byte, 0, 32*layout.SlotSize),
	}
	p.spec = spec
	p.plainPool.New = func() any { return make([]byte, layout.ChunkPlainSize) }
	p.blobPool.New = func() any { return make([]byte, layout.BlobPlainSize) }
	p.parPool.New = func() any { return make([]byte, layout.ParityShards*layout.ShardSize) }
	p.diskPool.New = func() any { return make([]byte, layout.BlobDiskSize) }

	p.wg.Add(workers)
	for i := 0; i < workers; i++ {
		go p.workerLoop()
	}
	go p.writeLoop()
	go p.parityLoop()
	return p
}

// Write 切块入队（返回 ≠ 落盘；错误延后）。
func (p *Pipeline) Write(b []byte) (int, error) {
	if err := p.errLoad(); err != nil {
		return 0, err
	}
	written := 0
	for len(b) > 0 {
		if p.chunkBuf == nil {
			p.chunkBuf = p.plainPool.Get().([]byte)[:0]
		}
		space := layout.ChunkPlainSize - len(p.chunkBuf)
		n := min(space, len(b))
		p.chunkBuf = append(p.chunkBuf, b[:n]...)
		b = b[n:]
		written += n
		if len(p.chunkBuf) == layout.ChunkPlainSize {
			p.enqueueChunk(p.chunkBuf, layout.ChunkPlainSize)
			p.chunkBuf = nil
		}
	}
	return written, nil
}

// Drain 排空流水线：冲刷部分块 → 等全部 goroutine 收尾 → 返回 (chunkCount, plainSize)。
func (p *Pipeline) Drain() (int64, int64, error) {
	if p.chunkBuf != nil {
		if len(p.chunkBuf) > 0 {
			p.enqueueChunk(p.chunkBuf, len(p.chunkBuf))
		} else {
			p.putBuf(&p.plainPool, p.chunkBuf)
		}
		p.chunkBuf = nil
	}
	close(p.encodeCh)
	p.wg.Wait()
	close(p.outCh)
	<-p.doneCh
	if p.finalKData > 0 {
		p.parCh <- parityMsg{flush: true, g: p.finalGroup, kData: p.finalKData}
	}
	close(p.parCh)
	<-p.parDone
	return p.chunkIdx, p.plainSize, p.errLoad()
}

func (p *Pipeline) enqueueChunk(plain []byte, plainLen int) {
	p.encodeCh <- &chunkJob{idx: p.chunkIdx, plain: plain, plainLen: plainLen}
	p.chunkIdx++
}

// workerLoop：GCM 加密 + 块内 RS + 拼装落盘缓冲。
func (p *Pipeline) workerLoop() {
	defer p.wg.Done()
	shards := make([][]byte, layout.ShardsPerBlob)
	for job := range p.encodeCh {
		if err := p.errLoad(); err == nil {
			if err := p.encodeJob(job, shards); err != nil {
				p.errStore(err)
				job.failed = true
			}
		} else {
			job.failed = true
		}
		p.outCh <- job
	}
}

// encodeJob：明文 → GCM → RS(256,128) → 拼装 384 槽（含 tag）。
func (p *Pipeline) encodeJob(job *chunkJob, shards [][]byte) error {
	nonce := make([]byte, layout.NonceSize)
	copy(nonce, p.noncePfx[:])
	binary.BigEndian.PutUint64(nonce[4:], uint64(job.idx))
	hdr := (&format.ChunkHeader{Index: job.idx, PlainLen: job.plainLen, Nonce: nonce}).Marshal()
	ct := p.aead.Seal(nil, nonce, job.plain[:job.plainLen], hdr)
	if len(hdr)+len(ct) > layout.BlobPlainSize {
		return errors.New("secvault: internal chunk overflow")
	}

	blob := p.blobPool.Get().([]byte)[:layout.BlobPlainSize]
	copy(blob, hdr)
	copy(blob[len(hdr):], ct)
	clear(blob[len(hdr)+len(ct):]) // 零填充区

	par := p.parPool.Get().([]byte)[:layout.ParityShards*layout.ShardSize]
	for i := 0; i < layout.DataShards; i++ {
		shards[i] = blob[i*layout.ShardSize : (i+1)*layout.ShardSize]
	}
	for i := 0; i < layout.ParityShards; i++ {
		pp := par[i*layout.ShardSize : (i+1)*layout.ShardSize]
		clear(pp)
		shards[layout.DataShards+i] = pp
	}
	if err := p.codec.Intra().Encode(shards); err != nil {
		p.putBuf(&p.blobPool, blob)
		p.putBuf(&p.parPool, par)
		return fmt.Errorf("secvault: intra encode: %w", err)
	}

	disk := p.diskPool.Get().([]byte)[:layout.BlobDiskSize]
	for i := 0; i < layout.ShardsPerBlob; i++ {
		off := i * layout.SlotSize
		copy(disk[off:off+layout.ShardSize], shards[i])
		copy(disk[off+layout.ShardSize:off+layout.SlotSize], crypto.ShardTag(shards[i]))
	}
	job.disk = disk
	job.blob = blob
	job.par = par

	// blob/par 的所有权移交 parityLoop（flush 后回收）——此处不得回收！
	// （v2 零拷贝移交：提前回收会导致 use-after-free，parity 编码读到被
	//   后续块覆写的缓冲，产生系统性的 parity 错误）
	p.putBuf(&p.plainPool, job.plain)
	job.plain = nil
	return nil
}

// writeLoop：按序写数据 blob + 移交 blob/par 引用给 parity 累加器。
func (p *Pipeline) writeLoop() {
	defer close(p.doneCh)
	pending := make(map[int64]*chunkJob)
	next := int64(0)
	for job := range p.outCh {
		pending[job.idx] = job
		for {
			j, ok := pending[next]
			if !ok {
				break
			}
			delete(pending, next)
			if !j.failed {
				if err := p.seekWrite(p.spec.DataBlobOffset(j.idx), j.disk); err != nil {
					p.errStore(err)
				} else {
					p.plainSize += int64(j.plainLen)
					p.groupChunks++
					p.parCh <- parityMsg{blob: j.blob, par: j.par}
					if p.groupChunks == layout.FileGroupChunks {
						p.parCh <- parityMsg{flush: true, g: p.groupsDone, kData: layout.FileGroupChunks}
						p.groupsDone++
						p.groupChunks = 0
					}
				}
			}
			if j.disk != nil {
				p.putBuf(&p.diskPool, j.disk)
			}
			next++
		}
	}
	if len(pending) > 0 {
		p.errStore(errors.New("secvault: internal job ordering loss"))
	}
	p.finalGroup = p.groupsDone
	p.finalKData = p.groupChunks
}

// parityLoop：后台累加组数据，组满即编码并写 64 个 parity blob（零读回零拷贝）。
func (p *Pipeline) parityLoop() {
	defer close(p.parDone)
	var blobs, pars [][]byte
	for msg := range p.parCh {
		if !msg.flush {
			blobs = append(blobs, msg.blob)
			pars = append(pars, msg.par)
			continue
		}
		if len(blobs) != msg.kData {
			p.errStore(fmt.Errorf("secvault: parity group %d got %d blobs want %d", msg.g, len(blobs), msg.kData))
		} else if err := p.writeParityGroup(msg.g, msg.kData, blobs, pars); err != nil {
			p.errStore(err)
		}
		for i := range blobs {
			p.putBuf(&p.blobPool, blobs[i])
			p.putBuf(&p.parPool, pars[i])
		}
		blobs = blobs[:0]
		pars = pars[:0]
	}
}

// writeParityGroup：文件级 RS(kData, m)，m 经 spec.ParityCountFor 得出——v2 恒 64（末组也
// 64）；v3 满组=M2Cap、末组=min(M2Cap,kLast)，1:1 上限由 Spec 统一保证。窗口直切 blob/par
// 视图（零拷贝）。窗口 0-7 落在 blob（256 数据列），窗口 8-11 落在 par（128 校验列），均连续。
func (p *Pipeline) writeParityGroup(g int64, kData int, blobs, pars [][]byte) error {
	m := int(p.spec.ParityCountFor(int64(kData))) // v2 恒 64（末组也 64）；v3 满组=M2Cap、末组=min(M2Cap,kLast)
	rs, err := p.codec.File(kData, m)
	if err != nil {
		return err
	}
	const win = 32
	shards := make([][]byte, kData+m)
	parOut := make([][]byte, m)
	for j0 := 0; j0 < layout.ShardsPerBlob; j0 += win {
		wc := win
		if j0+win > layout.ShardsPerBlob {
			wc = layout.ShardsPerBlob - j0
		}
		for i := 0; i < kData; i++ {
			if j0 < layout.DataShards {
				shards[i] = codec.SliceWindow(blobs[i], j0, wc)
			} else {
				shards[i] = codec.SliceWindow(pars[i], j0-layout.DataShards, wc)
			}
		}
		for q := range parOut {
			parOut[q] = make([]byte, wc*layout.ShardSize)
			shards[kData+q] = parOut[q]
		}
		if err := rs.Encode(shards); err != nil {
			return fmt.Errorf("secvault: file-level encode: %w", err)
		}
		for q := 0; q < m; q++ {
			p.slotBuf = p.slotBuf[:0]
			for c := 0; c < wc; c++ {
				col := parOut[q][c*layout.ShardSize : (c+1)*layout.ShardSize]
				p.slotBuf = append(p.slotBuf, col...)
				p.slotBuf = append(p.slotBuf, crypto.ShardTag(col)...)
			}
			off := p.spec.ParityBlobOffset(g, int64(kData), int64(q)) + int64(j0)*layout.SlotSize
			if err := p.seekWrite(off, p.slotBuf); err != nil {
				return err
			}
		}
	}
	return nil
}

// seekWrite 定点写。
func (p *Pipeline) seekWrite(off int64, b []byte) error {
	if _, err := p.dst.Seek(off, io.SeekStart); err != nil {
		return err
	}
	n, err := p.dst.Write(b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	return nil
}

func (p *Pipeline) errStore(err error) {
	p.errMu.Lock()
	if p.err == nil {
		p.err = err
	}
	p.errMu.Unlock()
}

func (p *Pipeline) errLoad() error {
	p.errMu.Lock()
	defer p.errMu.Unlock()
	return p.err
}

func (p *Pipeline) putBuf(pool *sync.Pool, buf []byte) {
	pool.Put(buf[:0])
}
