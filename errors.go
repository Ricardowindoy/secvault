package secvault

import (
	ierrors "secvault/internal/errors"
)

// 公共错误哨兵（internal/errors 的同值再导出，errors.Is 跨包语义不变）。
var (
	// ErrInvalidKey 主密钥长度不是 32 字节。
	ErrInvalidKey = ierrors.ErrBadKey
	// ErrNoManifest 尾部清单缺失：文件被截断、追加过数据或根本不是 secvault 文件。
	ErrNoManifest = ierrors.ErrNoManifest
	// ErrManifestAuth manifest 认证失败：密钥错误或清单被篡改。
	ErrManifestAuth = ierrors.ErrManifestAuth
	// ErrUnsupportedFormat 格式参数与 v2 不符。
	ErrUnsupportedFormat = ierrors.ErrUnsupportedFormat
	// ErrChunkUnrecoverable 块损坏超出全部纠错能力（块内 RS + 文件级 RS 均失败）。
	ErrChunkUnrecoverable = ierrors.ErrChunkUnrecoverable
	// ErrClosed 写入器已关闭。
	ErrClosed = ierrors.New("secvault: writer already closed")
	// ErrNegativeOffset 负偏移。
	ErrNegativeOffset = ierrors.New("secvault: negative offset")
)
