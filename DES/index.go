package DES

import (
	"crypto/des"
	"errors"
)

/**
不建议使用了 Des加密
*/
func Encrypt(origData, key []byte) ([]byte, error) {
	if len(origData) < 1 || len(key) < 1 {
		return nil, errors.New("wrong data or key")
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if len(origData)%bs != 0 {
		return nil, errors.New("wrong padding")
	}
	out := make([]byte, len(origData))
	dst := out
	for len(origData) > 0 {
		block.Encrypt(dst, origData[:bs])
		origData = origData[bs:]
		dst = dst[bs:]
	}
	return out, nil
}

/**
不建议使用了 Des解密
*/
func Decrypt(crypted, key []byte) ([]byte, error) {
	if len(crypted) < 1 || len(key) < 1 {
		return nil, errors.New("wrong data or key")
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(crypted))
	dst := out
	bs := block.BlockSize()
	if len(crypted)%bs != 0 {
		return nil, errors.New("wrong crypted size")
	}

	for len(crypted) > 0 {
		block.Decrypt(dst, crypted[:bs])
		crypted = crypted[bs:]
		dst = dst[bs:]
	}

	return out, nil
}
