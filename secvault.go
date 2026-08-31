// Package secvault 实现方案 C 视频加密容器：
// 分块 AES-256-GCM 认证加密 + 块内 RS(256,128) + 文件级 RS(128,64) 双层纠错，
// 支持透明读取修复与 scrub 就地修复。
//
// 架构（高内聚低耦合，依赖单向 API → engine → codec/format → crypto/layout）：
//
//	顶层门面：Writer / Reader / Verify / Scrub / Options / 错误哨兵
//	internal/layout   纯偏移数学（零依赖）
//	internal/format   块头/manifest/trailer 字节编解码
//	internal/crypto   HKDF/GCM/shard tag
//	internal/codec    RS 编码器缓存 + 窗口视图
//	internal/engine   写入流水线 + 读取容器（两级修复/GCM 终审）+ 巡检编排
//
// 格式细节见 FORMAT.md，实验与性能结论见 EXPERIMENTS.md。
package secvault

// 门面文件索引：
//   writer.go / reader.go / scrub.go / errors.go / consts.go
