package CBC

import (
	"fmt"
	"testing"
)

func TestAesDecrypt(t *testing.T) {
	orig := "hello world"
	key := "0123456789012345"
	fmt.Println("原文：", orig)
	encryptCode, _ := CBCEncrypt(orig, key)
	fmt.Println("密文：", encryptCode)
	decryptCode := CBCDecrypt(encryptCode, key)
	fmt.Println("解密结果：", decryptCode)
}
