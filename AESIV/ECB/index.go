package ECB

/*
全称Electronic CodeBook mode，电子密码本模式。
分组方式：将明文分组加密之后的结果直接称为密文分组。
优点：
一个分组损坏不影响其它分组。
可以并行加解密。
缺点：
相同的明文分组会转换为相同的密文分组。
无需破译密码就能操纵明文（每个分组独立且前后文无关，直接增加或删除一个分组不影响其它分组解密过程的正确性）。
ECB和CBC模式要求明文数据必须填充至长度为分组长度的整数倍。
需要填充的字节数为：paddingSize = blockSize - textLength % blockSize
ANSI X.923：填充序列的最后一个字节填paddingSize，其它填0。
ISO 10126：填充序列的最后一个字节填paddingSize， 其它填随机数。
PKCS7：填充序列的每个字节都填paddingSize。
*/
import "crypto/aes"

func AesEncrypt(src []byte, key []byte) (encrypted []byte) {
	cipher, _ := aes.NewCipher(generateKey(key))
	length := (len(src) + aes.BlockSize) / aes.BlockSize
	plain := make([]byte, length*aes.BlockSize)
	copy(plain, src)
	pad := byte(len(plain) - len(src))
	for i := len(src); i < len(plain); i++ {
		plain[i] = pad
	}
	encrypted = make([]byte, len(plain))
	// 分组分块加密
	for bs, be := 0, cipher.BlockSize(); bs <= len(src); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
		cipher.Encrypt(encrypted[bs:be], plain[bs:be])
	}

	return encrypted
}

func AesDecrypt(encrypted []byte, key []byte) (decrypted []byte) {
	cipher, _ := aes.NewCipher(generateKey(key))
	decrypted = make([]byte, len(encrypted))
	//
	for bs, be := 0, cipher.BlockSize(); bs < len(encrypted); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
		cipher.Decrypt(decrypted[bs:be], encrypted[bs:be])
	}

	trim := 0
	if len(decrypted) > 0 {
		trim = len(decrypted) - int(decrypted[len(decrypted)-1])
	}

	return decrypted[:trim]
}

func generateKey(key []byte) (genKey []byte) {
	genKey = make([]byte, 16)
	copy(genKey, key)
	for i := 16; i < len(key); {
		for j := 0; j < 16 && i < len(key); j, i = j+1, i+1 {
			genKey[j] ^= key[i]
		}
	}
	return genKey
}
