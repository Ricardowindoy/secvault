// Package crypto 提供 secvault 的密码学原语：
// HKDF 密钥派生、AES-256-GCM 构造、shard tag 计算与随机字节。
// 纯函数集合，不含任何布局知识。
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// AEAD 类型别名（cipher.AEAD 的方法集）。
type AEAD = cipher.AEAD

// DeriveKey 从主密钥 + fileID 盐派生 32B 子密钥。
func DeriveKey(master, fileID []byte, info string) []byte {
	r := hkdf.New(sha256.New, master, fileID, []byte(info))
	k := make([]byte, 32)
	if _, err := io.ReadFull(r, k); err != nil {
		panic("secvault: hkdf unreachable: " + err.Error())
	}
	return k
}

// NewGCM 构造 AES-256-GCM。
func NewGCM(key []byte) (AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// ShardTag 截断 SHA-256：仅用于意外损坏定位（非认证，认证靠 GCM）。
func ShardTag(payload []byte) []byte {
	s := sha256.Sum256(payload)
	return s[:16]
}

// VerifyTag 常量时间比较 tag。
func VerifyTag(payload, tag []byte) bool {
	if len(tag) != 16 {
		return false
	}
	t := ShardTag(payload)
	return subtle.ConstantTimeCompare(t[:], tag) == 1
}

// RandomBytes 密码学随机。
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("secvault: crypto/rand: %w", err)
	}
	return b, nil
}
