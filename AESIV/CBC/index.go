package CBC

/*
全称Cipher Block Chaining mode，密码分组链接模式。
分组方式：将明文分组与前一个密文分组进行XOR运算，然后再进行加密。每个分组的加解密都依赖于前一个分组。而第一个分组没有前一个分组，因此需要一个初始化向量（initialization vector）。
优点：
加密结果与前文相关，有利于提高加密结果的随机性。
可并行解密。
缺点
无法并行加密。
一个分组损坏，如果密文长度不变，则两个分组受影响。
一个分组损坏，如果密文长度改变，则后面所有分组受影响。
ANSI X.923：填充序列的最后一个字节填paddingSize，其它填0。
ISO 10126：填充序列的最后一个字节填paddingSize， 其它填随机数。
PKCS7：填充序列的每个字节都填paddingSize。
*/
import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	p7 "zcbEND/PKCSPadding/PKCS7"
)

/**
输入key的长度必须为16, 24或者32
*/
func CBCEncrypt(orig string, key string) (string, error) {
	// 转成字节数组
	origData := []byte(orig)
	k := []byte(key)
	// 分组秘钥
	// NewCipher该函数限制了输入k的长度必须为16, 24或者32
	block, _ := aes.NewCipher(k)
	// 获取秘钥块的长度
	blockSize := block.BlockSize()
	// 补全码
	err, origData := p7.PKCS7Padding(origData, blockSize)
	if err != nil {
		return "", err
	}
	// 加密模式
	blockMode := cipher.NewCBCEncrypter(block, k[:blockSize])
	// 创建数组
	cryted := make([]byte, len(origData))
	// 加密
	blockMode.CryptBlocks(cryted, origData)
	return base64.StdEncoding.EncodeToString(cryted), nil
}
func CBCDecrypt(cryted string, key string) string {
	// 转成字节数组
	crytedByte, _ := base64.StdEncoding.DecodeString(cryted)
	k := []byte(key)
	// 分组秘钥
	block, _ := aes.NewCipher(k)
	// 获取秘钥块的长度
	blockSize := block.BlockSize()
	// 加密模式
	blockMode := cipher.NewCBCDecrypter(block, k[:blockSize])
	// 创建数组
	orig := make([]byte, len(crytedByte))
	// 解密
	blockMode.CryptBlocks(orig, crytedByte)
	// 去补全码
	orig = p7.PKCS7UnPadding(orig)
	return string(orig)
}
