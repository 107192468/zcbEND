package ECB

import (
	"fmt"
	"testing"
)

func TestAESDecrypt(t *testing.T) {
	orig := "hello world"
	key := "0123456789012345"
	fmt.Println("原文：", orig)
	encryptCode := AesEncrypt([]byte(orig), []byte(key))
	fmt.Println("密文：" , string(encryptCode))
	decryptCode := AesDecrypt(encryptCode, []byte(key))
	fmt.Println("解密结果：", string(decryptCode))
}