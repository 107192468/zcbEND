package TripleDES

import (
	"crypto/des"
	"encoding/base64"
	"github.com/sirupsen/logrus"
	"zcbEND/DES"
	p7 "zcbEND/PKCSPadding/PKCS7"
)

/**
  不推荐使用，推荐aes
*/
func TriPleEncryptString(plaintext, key string) string {
	nb, err := TripleEcbDesEncrypt([]byte(plaintext), []byte(key))
	if err == nil {
		return base64.StdEncoding.EncodeToString(nb)
	} else {
		logrus.Error("TripleEcbDesEncrypt", err)
	}
	return ""
}

/**
  不推荐使用，推荐aes
*/
func TriPleDecryptString(ciphertext, key string) string {
	b, err := base64.StdEncoding.DecodeString(ciphertext)
	if err == nil {
		nb, err := TripleEcbDesDecrypt(b, []byte(key))
		if err == nil {
			return string(nb)
		}
	}
	return ""
}

/**
  不推荐使用，推荐aes
*/
func TripleEcbDesEncrypt(origData, key []byte) ([]byte, error) {
	tkey := make([]byte, 24, 24)
	copy(tkey, key)
	k1 := tkey[:8]
	k2 := tkey[8:16]
	k3 := tkey[16:]

	block, err := des.NewCipher(k1)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	err, origData = p7.PKCS7Padding(origData, bs)
	if err != nil {
		return nil, err
	}
	buf1, err := DES.Encrypt(origData, k1)
	if err != nil {
		return nil, err
	}
	buf2, err := DES.Decrypt(buf1, k2)
	if err != nil {
		return nil, err
	}
	out, err := DES.Encrypt(buf2, k3)
	if err != nil {
		return nil, err
	}
	return out, nil
}

/**
  不推荐使用，推荐aes
*/
func TripleEcbDesDecrypt(crypted, key []byte) ([]byte, error) {
	tkey := make([]byte, 24, 24)
	copy(tkey, key)
	k1 := tkey[:8]
	k2 := tkey[8:16]
	k3 := tkey[16:]
	buf1, err := DES.Decrypt(crypted, k3)
	if err != nil {
		return nil, err
	}
	buf2, err := DES.Encrypt(buf1, k2)
	if err != nil {
		return nil, err
	}
	out, err := DES.Decrypt(buf2, k1)
	if err != nil {
		return nil, err
	}
	out = p7.PKCS7UnPadding(out)
	return out, nil
}
