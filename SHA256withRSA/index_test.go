package SHA256withRSA

import (
	"fmt"
	"testing"
)

func TestRsaWithSHA256Base64(t *testing.T) {
	key := "B19F79363ec60767"
	name, error := RsaWithSHA256Base64("this is test 中文", []byte(key))
	if error != nil {
		panic(error)
	}
	fmt.Println(name)

}
