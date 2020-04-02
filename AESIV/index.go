package AESIV

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	logs "github.com/sirupsen/logrus"
)

//AES加密
func AESBase64Encrypt(origin_data string, key string, iv string) (base64_result string, err error) {
	var block cipher.Block
	if block, err = aes.NewCipher([]byte(key)); err != nil {
		logs.Info(err)
		return
	}
	encrypt := cipher.NewCBCEncrypter(block, []byte(iv))
	var source []byte = PKCS5Padding([]byte(origin_data), 16)
	var dst []byte = make([]byte, len(source))
	encrypt.CryptBlocks(dst, source)
	base64_result = base64.StdEncoding.EncodeToString(dst)
	return
}

//AES解密
func AESBase64Decrypt(encrypt_data string, key string, iv string) (origin_data string, err error) {
	var block cipher.Block
	if block, err = aes.NewCipher([]byte(key)); err != nil {
		logs.Info(err)
		return
	}
	encrypt := cipher.NewCBCDecrypter(block, []byte(iv))

	var source []byte
	if source, err = base64.StdEncoding.DecodeString(encrypt_data); err != nil {
		logs.Info(err)
		return
	}
	var dst []byte = make([]byte, len(source))
	encrypt.CryptBlocks(dst, source)
	origin_data = string(PKCS5Unpadding(dst))
	return
}

//AES--PKCS5包装
func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

//AES--PKCS5解包装
func PKCS5Unpadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
