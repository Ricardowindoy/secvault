// Package errors 定义 secvault 全部错误哨兵。
// 顶层包以 var 别名再导出，errors.Is 跨包语义不变；internal 各包只依赖本包，
// 避免内部实现反向依赖公共 API 层。
package errors

import "errors"

var (
	// ErrNoManifest 尾部清单缺失：文件被截断、追加过数据或根本不是 secvault 文件。
	ErrNoManifest = errors.New("secvault: manifest trailer not found (truncated, appended, or not a secvault file)")
	// ErrManifestAuth manifest 认证失败：密钥错误或清单被篡改。
	ErrManifestAuth = errors.New("secvault: manifest authentication failed (wrong key or corrupted)")
	// ErrUnsupportedFormat 格式参数与 v2 不符。
	ErrUnsupportedFormat = errors.New("secvault: unsupported format parameters")
	// ErrChunkUnrecoverable 块损坏超出全部纠错能力（块内 RS + 文件级 RS 均失败）。
	ErrChunkUnrecoverable = errors.New("secvault: chunk damaged beyond recovery")
	// ErrGCMOnlyCorrupted gcm-only 容器 GCM.Open 失败：检测到损坏/篡改，
	// 本类别定义如此（损坏→调用方重拉），无修复路径。
	ErrGCMOnlyCorrupted = errors.New("secvault: gcm-only container corrupted (re-pull required)")
	// ErrBadKey 主密钥长度不是 32 字节。
	ErrBadKey = errors.New("secvault: master key must be exactly 32 bytes")
)

// New 与 Wrap 便捷函数（内部包用，避免各自 import errors 标准库歧义）。
func New(msg string) error { return errors.New(msg) }
func Wrap(err error, msg string) error {
	return fmtErr(msg, err)
}

// Is 转发标准库 errors.Is（内部包统一入口，避免 import 歧义）。
func Is(err, target error) bool { return errors.Is(err, target) }

func fmtErr(msg string, err error) error {
	if err == nil {
		return nil
	}
	return &wrapped{msg: msg, err: err}
}

type wrapped struct {
	msg string
	err error
}

func (w *wrapped) Error() string { return w.msg + ": " + w.err.Error() }
func (w *wrapped) Unwrap() error { return w.err }
