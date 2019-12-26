package PKCS7

import (
	"bytes"
	"errors"
)

/**
	PKCS7是当下各大加密算法都遵循的数据填充算法，且 OpenSSL 加密算法簇的默认填充算法就是 PKCS7。
	AES-128,       AES-192,       AES-256 的数据块长度分别为
    128/8=16bytes, 192/8=24bytes, 256/8=32bytes。
	其实PKCS7理解起来非常简单，使用需填充长度的数值 paddingSize 所表示的ASCII码 paddingChar = chr(paddingSize)对数据进行冗余填充。
	比如 AES-128的数据块长度是 16bytes，使用PKCS7进行填充时，填充的长度范围是 1 ~ 16。注意，当待加密数据长度为 16 的整数倍时，填充的长度反而是最大的，要填充 16 字节，为什么呢？因为 "PKCS7" 拆包时会按协议取最后一个字节所表征的数值长度作为数据填充长度，如果因真实数据长度恰好为 16 的整数倍而不进行填充，则拆包时会导致真实数据丢失。
	为什么是冗余填充呢？因为即便你的数据长度符合blockSize的整数倍时，也需要填充，填充的长度反而是最大的，要填充blockSize个char(blockSize)字符在数据尾部，这样牺牲了数据长度的做法是为了更为灵活透明的去解包数据，发送端和接收端不需要约定好blockSize，接收端总能通过数据包的最后一个字符得到填充的数据长度。
	当我们拿到一串PKCS7填充的数据时，取其最后一个字符paddingChar，此字符的ASCII码的十进制ord(paddingChar)即为填充的数据长度paddingSize，读取真实数据时去掉填充长度即可substr(content, 0, -paddingSize)。
	填充示例，比如数据块blockSize为 8
	h<0x07><0x07><0x07><0x07><0x07><0x07><0x07> 7
	he<0x06><0x06><0x06><0x06><0x06><0x06> 6
	hel<0x05><0x05><0x05><0x05><0x05> 5
	hell<0x04><0x04><0x04><0x04> 4
	hello<0x03><0x03><0x03> 3
	hello <0x02><0x02> 2
	hello w<0x01> 1
	hello wo<0x08><0x08><0x08><0x08><0x08><0x08><0x08><0x08> 8 // 数据块
	hello wor<0x07><0x07><0x07><0x07><0x07><0x07><0x07> 7
	hello word<0x06><0x06><0x06><0x06><0x06><0x06> 6
*/

func PKCS7Padding(cipherText []byte, blockSize int) (error, []byte) {
	if 255 < blockSize || 0 >= blockSize {
		return errors.New("the block size pkcs7 can padding is (0 ~ 255] "), nil
	}
	paddingSize := blockSize - (len(cipherText) % blockSize)
	padtext := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)
	return nil, append(cipherText, padtext...)
}
func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func PKCS5padding(cipherText []byte)(error, []byte){
	return PKCS7Padding(cipherText,8)
}