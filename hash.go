package crypto

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
)

// 对字符串进行md5哈希算法
func Md5(src interface{}) string {
	srcByte := getByteArray(src)
	if srcByte == nil {
		return ""
	}
	h := md5.New()
	h.Write(srcByte)
	return hex.EncodeToString(h.Sum(nil))
}

// 对字符串进行sha1哈希算法
func Sha1(src interface{}) string {
	srcByte := getByteArray(src)
	if srcByte == nil {
		return ""
	}
	h := sha1.New()
	h.Write(srcByte)
	return hex.EncodeToString(h.Sum(nil))
}

func getByteArray(src interface{}) []byte {
	var srcByte []byte
	switch value := src.(type) {
	case string:
		srcByte = []byte(value)
	case []byte:
		srcByte = value
	default:
		srcByte = nil

	}
	return srcByte
}
