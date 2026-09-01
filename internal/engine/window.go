package engine

import (
	"io"

	"secvault/internal/codec"
	"secvault/internal/crypto"
	"secvault/internal/layout"
)

// readWindow 读取 wc 个连续槽（每槽 SlotSize=ShardSize+TagSize），逐槽验证 tag。
// 返回 (payload, ok, err)：
//   - err != nil：读取失败（io.EOF 容忍，继续走 tag 验证——短读几乎必然 tag 失败）；
//   - ok == false 且 err == nil：任一槽 tag 验证失败；
//   - ok == true：全部通过，payload 为抽出载荷拼接（长度 wc*ShardSize）。
//
// 共享于 container.RebuildMissing 与 scrub.rebuildFileParity 两处文件级扫窗读；
// 调用方按原语义决定：erasure（两因同判）或 读错误显式传播 / tag 失败静默中止。
func readWindow(src io.ReaderAt, off int64, wc int) ([]byte, bool, error) {
	raw := make([]byte, wc*layout.SlotSize)
	if _, err := src.ReadAt(raw, off); err != nil && err != io.EOF {
		return nil, false, err
	}
	for cIdx := 0; cIdx < wc; cIdx++ {
		p := raw[cIdx*layout.SlotSize : cIdx*layout.SlotSize+layout.ShardSize]
		t := raw[cIdx*layout.SlotSize+layout.ShardSize : (cIdx+1)*layout.SlotSize]
		if !crypto.VerifyTag(p, t) {
			return nil, false, nil
		}
	}
	return codec.ExtractPayloads(raw, wc), true, nil
}
