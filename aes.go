package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

type AES struct {
	Key []byte // 密钥
}

// 加密
func (s *AES) Encrypt(src interface{}) string {
	// 检查密钥的长度
	size := len(s.Key)
	if size != 16 && size != 24 && size != 32 {
		return ""
	}

	// 检查src的类型
	var plainText []byte
	switch value := src.(type) {
	case string:
		plainText = []byte(value)
	case []byte:
		plainText = value
	default:
		plainText = nil
	}
	if plainText == nil {
		return ""
	}

	// 创建新密码块
	block, err := aes.NewCipher(s.Key)
	if err != nil {
		return ""
	}

	// 填充数据
	blockSize := block.BlockSize()
	padding := blockSize - len(plainText)%blockSize
	paddingByte := bytes.Repeat([]byte{byte(padding)}, padding)
	plainText = append(plainText, paddingByte...)

	// 创建一个CBC模式加密块
	iv := make([]byte, aes.BlockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	cipherText := make([]byte, len(plainText))

	// 开始加密
	blockMode.CryptBlocks(cipherText, plainText)
	return base64.StdEncoding.EncodeToString(cipherText)
}

// 解密
func (s *AES) Decrypt(src interface{}) []byte {
	// 检查密钥的长度
	size := len(s.Key)
	if size != 16 && size != 24 && size != 32 {
		return nil
	}

	// 检查src的类型
	var str string
	switch value := src.(type) {
	case string:
		str = value
	case []byte:
		str = string(value)
	default:
		str = ""
	}
	if str == "" {
		return nil
	}

	cipherText, _ := base64.StdEncoding.DecodeString(str)

	// 创建新密码块
	block, err := aes.NewCipher(s.Key)
	if err != nil {
		return nil
	}

	// 创建一个CBC模式解密块
	iv := make([]byte, aes.BlockSize)
	blockMode := cipher.NewCBCDecrypter(block, iv)
	plainText := make([]byte, len(cipherText))

	// 开始解密
	blockMode.CryptBlocks(plainText, cipherText)

	// 去除填充数据
	length := len(plainText)
	if length == 0 {
		return nil
	}
	unPadding := int(plainText[length-1])
	return plainText[:(length - unPadding)]
}
