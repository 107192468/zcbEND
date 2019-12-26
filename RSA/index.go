package RSA

/**
	公钥加密标准（Public Key Cryptography Standards, PKCSPadding），此一标准的设计与发布皆由RSA信息安全公司所制定。
PKCS标准汇总
版本	名称	简介
PKCSPadding #1	2.1	RSA密码编译标准（RSA Cryptography Standard）	定义了RSA的数理基础、公/私钥格式，以及加/解密、签/验章的流程。1.5版本曾经遭到攻击。
PKCSPadding #2	-	撤销	原本是用以规范RSA加密摘要的转换方式，现已被纳入PKCS#1之中。
PKCSPadding #3	1.4	DH密钥协议标准（Diffie-Hellman key agreement Standard）	规范以DH密钥协议为基础的密钥协议标准。其功能，可以让两方通过金议协议，拟定一把会议密钥(Session key)。
PKCSPadding #4	-	撤销	原本用以规范转换RSA密钥的流程。已被纳入PKCS#1之中。
PKCSPadding #5	2.0	密码基植加密标准（Password-based Encryption Standard）	参见RFC 2898与PBKDF2。
PKCSPadding #6	1.5	证书扩展语法标准（Extended-Certificate Syntax Standard）	将原本X.509的证书格式标准加以扩充。
PKCSPadding #7	1.5	密码消息语法标准（Cryptographic Message Syntax Standard）	参见RFC 2315。规范了以公开密钥基础设施（PKI）所产生之签名/密文之格式。其目的一样是为了拓展数字证书的应用。其中，包含了S/MIME与CMS。
PKCSPadding #8	1.2	私钥消息表示标准（Private-Key Information Syntax Standard）.	Apache读取证书私钥的标准。
PKCSPadding #9	2.0	选择属性格式（Selected Attribute Types）	定义PKCS#6、7、8、10的选择属性格式。
PKCSPadding #10	1.7	证书申请标准（Certification Request Standard）	参见RFC 2986。规范了向证书中心申请证书之CSR（certificate signing request）的格式。
PKCSPadding #11	2.20	密码设备标准接口（Cryptographic Token Interface (Cryptoki)）	定义了密码设备的应用程序接口（API）之规格。
PKCSPadding #12	1.0	个人消息交换标准（Personal Information Exchange Syntax Standard）	定义了包含私钥与公钥证书（public key certificate）的文件格式。私钥采密码(password)保护。常见的PFX就履行了PKCS#12。
PKCSPadding #13	–	椭圆曲线密码学标准（Elliptic curve cryptography Standard）	制定中。规范以椭圆曲线密码学为基础所发展之密码技术应用。椭圆曲线密码学是新的密码学技术，其强度与效率皆比现行以指数运算为基础之密码学算法来的优秀。然而，该算法的应用尚不普及。
PKCSPadding #14	–	拟随机数产生器标准（Pseudo-random Number Generation）	制定中。规范拟随机数产生器的使用与设计。
PKCSPadding #15	1.1	密码设备消息格式标准（Cryptographic Token Information Format Standard）	定义了密码设备内部数
*/
import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

/**
公钥加密-分段
*/
func RsaEncrypt(src, publicKeyByte []byte) (bytesEncrypt []byte, err error) {
	block, _ := pem.Decode(publicKeyByte)
	if block == nil {
		return nil, errors.New("获取公钥失败")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)

	if err != nil {
		return
	}
	keySize, srcSize := publicKey.(*rsa.PublicKey).Size(), len(src)
	pub := publicKey.(*rsa.PublicKey)
	//logs.Debug("密钥长度：", keySize, "\t明文长度：\t", srcSize)
	//单次加密的长度需要减掉padding的长度，PKCS1为11
	offSet, once := 0, keySize-11
	buffer := bytes.Buffer{}
	for offSet < srcSize {
		endIndex := offSet + once
		if endIndex > srcSize {
			endIndex = srcSize
		}
		// 加密一部分
		bytesOnce, err := rsa.EncryptPKCS1v15(rand.Reader, pub, src[offSet:endIndex])
		if err != nil {
			return nil, err
		}
		buffer.Write(bytesOnce)
		offSet = endIndex
	}
	bytesEncrypt = buffer.Bytes()
	return
}

/**
私钥解密-分段
*/
func RsaDecrypt(src, privateKeyByte []byte) (bytesDecrypt []byte, err error) {
	block, _ := pem.Decode(privateKeyByte)
	if block == nil {
		return nil, errors.New("获取私钥失败")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return
	}
	private := privateKey.(*rsa.PrivateKey)
	keySize, srcSize := private.Size(), len(src)
	//logs.Debug("密钥长度：", keySize, "\t密文长度：\t", srcSize)
	var offSet = 0
	var buffer = bytes.Buffer{}
	for offSet < srcSize {
		endIndex := offSet + keySize
		if endIndex > srcSize {
			endIndex = srcSize
		}
		bytesOnce, err := rsa.DecryptPKCS1v15(rand.Reader, private, src[offSet:endIndex])
		if err != nil {
			return nil, err
		}
		buffer.Write(bytesOnce)
		offSet = endIndex
	}
	bytesDecrypt = buffer.Bytes()
	return
}
