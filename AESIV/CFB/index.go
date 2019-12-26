package CFB

/*
全称Cipher FeedBack mode，密文反馈模式。
分组方式：前一个密文分组会被送回到密码算法的输入端（具体见下图）。
在CBC和EBC模式中，明文分组都是通过密码算法进行加密的。而在CFB模式中，明文分组并没有通过加密算法直接进行加密，明文分组和密文分组之间只有一个XOR。
CFB模式是通过将“明文分组”与“密码算法的输出”进行XOR运行生成“密文分组”。CFB模式中由密码算法生成的比特序列称为密钥流（key stream）。密码算法相当于密钥流的伪随机数生成器，而初始化向量相当于伪随机数生成器的种子。（CFB模式有点类似一次性密码本。）
优点：
支持并行解密。
不需要填充（padding）。
缺点：
不能抵御重放攻击（replay attack）。
不支持并行加密。
*/
// Load your secret key from a safe place and reuse it across multiple
// NewCipher calls. (Obviously don't use this example key for anything
// real.) If you want to convert a passphrase to a key, use a suitable
// package like bcrypt or scrypt.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

func CFBDecrypter(ciphertext, key []byte) (error, []byte) {

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		return errors.New("ciphertext too short"), nil
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)
	return nil, ciphertext
}

func CFBEncrypter(plaintext, key []byte) (error, []byte) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return err, nil
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err, nil
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.
	return nil, ciphertext
}
