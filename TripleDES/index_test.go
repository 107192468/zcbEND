package TripleDES

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func TestTriPleDecryptString(t *testing.T) {
	key := "B19F79363ec60767"
	name, _ := TripleEcbDesEncrypt([]byte("this is test 中文"), []byte(key))
	nameStr := base64.StdEncoding.EncodeToString(name)
	fmt.Println(nameStr)
	nam, _ := TripleEcbDesDecrypt(name, []byte(key))
	fmt.Println(string(nam))
}
