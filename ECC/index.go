package ECC

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"zcbEND/crypto"
)

/**
ECC是建立在基于椭圆曲线的离散对数问题上的密码体制，给定椭圆曲线上的一个点G，并选取一个整数k，求解K=kG很容易(注意根据kG求解出来的K也是椭圆曲线上的一个点)；反过来，在椭圆曲线上给定两个点K和G，若使K=kG，求整数k是一个难题。ECC就是建立在此数学难题之上,这一数学难题称为椭圆曲线离散对数问题。其中椭圆曲线上的点K则为公钥(注意公钥K不是一个整数而是一个椭圆曲线点，这个点在OpenSSL里面是用结构体EC_Point来表示的，为了加深理解，建议自行下载OpenSSL进行查看学习)，整数k则为私钥(实际上是一个大整数)。
不知我说明白了没有，这是网上的一位网友总结的，供参考：
考虑如下等式：K=kG [其中 K,G为Ep(a,b)上的点，k为小于n（n是点G的阶）的整数]，不难发现，给定k和G，根据加法法则，计算K很容易；但给定K和G，求k就相对困难了。这就是椭圆曲线加密算法采用的难题，我们把点G称为基点（base point）。
现在我们描述一个利用椭圆曲线进行加密通信的过程：
1、用户A选定一条椭圆曲线Ep(a,b)，并取椭圆曲线上一点，作为基点G。
2、用户A选择一个私有密钥k，并生成公开密钥K=kG。
3、用户A将Ep(a,b)和点K，G传给用户B。
4、用户B接到信息后 ，将待传输的明文编码到Ep(a,b)上一点M（编码方法很多，这里不作讨论），并产生一个随机整数r。
5、用户B计算点C1=M+rK；C2=rG。
6、用户B将C1、C2传给用户A。
7、用户A接到信息后，计算C1-kC2，结果就是点M。因为 C1-kC2=M+rK-k(rG)=M+rK-r(kG)=M
      再对点M进行解码就可以得到明文。
在这个加密通信中，如果有一个偷窥者H ，他只能看到Ep(a,b)、K、G、C1、C2，而通过K、G 求k 或通过C2、G求r 都是相对困难的，因此，H无法得到A、B间传送的明文信息。
密码学中，描述一条Fp上的椭圆曲线，常用到六个参量：T=(p,a,b,n,x,y)。
（p 、a 、b） 用来确定一条椭圆曲线，p为素数域内点的个数，a和b是其内的两个大数；
x,y为G基点的坐标，也是两个大数；
n为点G基点的阶；
以上六个量就可以描述一条椭圆曲线，有时候我们还会用到h(椭圆曲线上所有点的个数p与n相除的整数部分)。
*/
/**
ASN.1
Abstract Syntax Notation One (ASN.1)是一种接口描述语言，提供了一种平台无关的描述数据结构的方式。ASN.1是ITU-T、ISO、以及IEC的标准，广泛应用于电信和计算机网络领域，尤其是密码学领域。
ASN.1与大家熟悉的Protocol Buffers和Apache Thrift非常相似，都可以通过schema来定义数据结构，提供跨平台的数据序列化和反序列化能力。不同的是，ASN.1早在1984年就被定为标准，比这两者要早很多年，并得到了广泛的应用，被用来定义了很多世界范围内广泛使用的数据结构，有大量的RFC文档使用ASN.1定义协议、数据格式等。比如https所使用的X.509证书结构，就是使用ASN.1定义的。
ASN.1定义了若干基础的数据类型和结构类型：
Topic	        	Description
Basic Types	  		BIT STRING
					BOOLEAN
					INTEGER
					NULL
					OBJECT IDENTIFIER
					OCTET STRING
String Types		BMPString
					IA5String
					PrintableString
					TeletexString
					UTF8String
Constructed Types	SEQUENCE
					SET
					CHOICE
上述的基础类型可以在https://msdn.microsoft.com/en-us/library/windows/desktop/bb540789(v=vs.85).aspx找到详尽的解释。我们可以使用这些来描述我们自己的数据结构：
    FooQuestion ::= SEQUENCE {
        trackingNumber INTEGER,
        question       IA5String
    }
如上定义了一个名为FooQuestion的数据结构。它是一个SEQUENCE结构，包含了一个INTEGER一个IA5String 一个具体的FooQuestion可以描述为：
    myQuestion FooQuestion ::= {
        trackingNumber     5,
        question           "Anybody there?"
    }
用ASN.1定义的数据结构实例，可以序列化为二进制的BER、文本类型的JSON、XML等。
Object Identifier
Object Identifier (OID)https://en.wikipedia.org/wiki/Object_identifier 是一项由ITU和ISO/IEC制定的标准，用来唯一标识对象、概念，或者其它任何具有全球唯一特性的东西。
一个OID表现为用.分隔的一串数字，比如椭圆曲线secp256r1的OID是这样：
1.2.840.10045.3.1.7
其每个数字的含义如下：
iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3) prime(1) 7
OID是全局统一分配的，全部的OID可以看做一棵多叉树，每一个有效的OID表现为树上的一个节点。当前所有的OID可以在这里找到。
OID是ASN.1的基本类型。

BER & DER
Basic Encoding Rules (BER)https://en.wikipedia.org/wiki/X.690#BER_encoding是一种自描述的ASN.1数据结构的二进制编码格式。每一个编码后的BER数据依次由数据类型标识（Type identifier），长度描述（Length description）, 实际数据（actual Value）排列而成，即BER是一种二进制TLV编码。TLV编码的一个好处，是数据的解析者不需要读取完整的数据，仅从一个不完整的数据流就可以开始解析。

Distinguished Encoding Rules (DER)是BER的子集，主要是消除了BER的一些不确定性的编码规则，比如在BER中Boolean类型true的value字节，可以为任何小于255大于0的整数，而在DER中，value字节只能为255。DER的这种确定性，保证了一个ASN.1数据结构，在编码为为DER后，只会有一种正确的结果。这使得DER更适合用在数字签名领域，比如X.509中广泛使用了DER。

关于各种ASN.1数据类型是如何被编码为DER，可以在这里找到详尽的解释。

如果有DER数据需要解析查看内容，这里有一个很方便的在线工具http://lapo.it/asn1js/。
用DER来编码ASN.1小节中自定义的myQuestion如下：
0x30 0x13 0x02 0x01 0x05 0x16 0x0e 0x41 0x6e 0x79 0x62 0x6f 064 0x79 0x20 0x74 0x68 0x65 0x72 0x65 0x3f
---  ---  ---  ---  ---  ---  ---  --------------------------------------------------------------------
 ^    ^    ^    ^    ^    ^    ^                                   ^
 |    |    |    |    |    |    |                                   |
 |    |    | INTEGER | IA5STRING                                   |
 |    |    | LEN=1   | TAG     |                                   |
 |    |    |         |         |                                   |
 |    | INTEGER   INTEGER   IA5STRING                          IA5STRING
 |    | TAG       VALUE(5)  LEN=14                             VALUE("Anybody there?")
 |    |
 |    |  ----------------------------------------------------------------------------------------------
 |    |                                              ^
 |  SEQUENCE LEN=19                                  |
 |                                                   |
SEQUENCE TAG                                  SEQUENCE VALUE
PEM
DER格式是ASN.1数据的二进制编码，计算机处理方便，但不利于人类处理，比如不方便直接在邮件正文中粘贴发送。PEM是DER格式的BASE64编码。除此之外，PEM在DER的BASE64前后各增加了一行，用来标识数据内容。示例如下：

-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMYfnvWtC8Id5bPKae5yXSxQTt
+Zpul6AnnZWfI2TtIarvjHBFUtXRo96y7hoL4VWOPKGCsRqMFDkrbeUjRrx8iL91
4/srnyf6sh9c8Zk04xEOpK1ypvBz+Ks4uZObtjnnitf0NBGdjMKxveTq+VE7BWUI
yQjtQ8mbDOsiLLvh7wIDAQAB
-----END PUBLIC KEY-----
X.509
X.509是一项描述公钥证书结构的标准，广泛使用在HTTPS协议中，定义在RFC 3280

X.509使用ASN.1来描述公钥证书的结构，通常编码为DER格式，也可以进一步BASE64编码为可打印的PEM格式。V3版本的X.509结构如下：

    Certificate  ::=  SEQUENCE  {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  }

    TBSCertificate  ::=  SEQUENCE  {
        version         [0]  EXPLICIT Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        extensions      [3]  EXPLICIT Extensions OPTIONAL
                             -- If present, version MUST be v3
        }

   Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }

   CertificateSerialNumber  ::=  INTEGER

   Validity ::= SEQUENCE {
        notBefore      Time,
        notAfter       Time }

   Time ::= CHOICE {
        utcTime        UTCTime,
        generalTime    GeneralizedTime }

   UniqueIdentifier  ::=  BIT STRING

   SubjectPublicKeyInfo  ::=  SEQUENCE  {
        algorithm            AlgorithmIdentifier,
        subjectPublicKey     BIT STRING  }

   Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension

   Extension  ::=  SEQUENCE  {
        extnID      OBJECT IDENTIFIER,
        critical    BOOLEAN DEFAULT FALSE,
        extnValue   OCTET STRING  }

SubjectPublicKeyInfo
如上一节所示，SubjectPublicKeyInfo是公钥证书格式X.509的组成部分。SubjectPublicKeyInfo结构使用ASN.1描述，其中使用了椭圆曲线公私钥加密算法的SubjectPublicKeyInfo结构定义在RFC 5480

其结构如下：

   SubjectPublicKeyInfo  ::=  SEQUENCE  {
        algorithm            AlgorithmIdentifier,
        subjectPublicKey     BIT STRING
   }

   AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm   OBJECT IDENTIFIER,
        parameters  ANY DEFINED BY algorithm OPTIONAL
   }
可以看到AlgorithmIdentifier也是一个SEQUENCE，其parameters部分取决于algorithm的具体取值。

对不限制的ECC公钥使用算法的场景，algorithm取值：

1.2.840.10045.2.1

即： iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1
在该种类场景下，parameters的定义如下：

    ECParameters ::= CHOICE {
        namedCurve         OBJECT IDENTIFIER
    }
即parameters指定了ECC公钥所使用的椭圆曲线。其可选的值有：

    secp192r1 OBJECT IDENTIFIER ::= {
        iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3) prime(1) 1 }

    sect163k1 OBJECT IDENTIFIER ::= {
        iso(1) identified-organization(3) certicom(132) curve(0) 1 }

    sect163r2 OBJECT IDENTIFIER ::= {
        iso(1) identified-organization(3) certicom(132) curve(0) 15 }

    secp224r1 OBJECT IDENTIFIER ::= {
        iso(1) identified-organization(3) certicom(132) curve(0) 33 }

    sect233k1 OBJECT IDENTIFIER ::= {
        iso(1) identified-organization(3) certicom(132) curve(0) 26 }

    sect233r1 OBJECT IDENTIFIER ::= {
        iso(1) identified-organization(3) certicom(132) curve(0) 27 }

    secp256r1 OBJECT IDENTIFIER ::= {
        iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3) prime(1) 7 }

    sect283k1 OBJECT IDENTIFIER ::= {
        iso(1) identified-organization(3) certicom(132) curve(0) 16 }

    sect283r1 OBJECT IDENTIFIER ::= {
        iso(1) identified-organization(3) certicom(132) curve(0) 17 }

    secp384r1 OBJECT IDENTIFIER ::= {
        iso(1) identified-organization(3) certicom(132) curve(0) 34 }

    sect409k1 OBJECT IDENTIFIER ::= {
        iso(1) identified-organization(3) certicom(132) curve(0) 36 }

    sect409r1 OBJECT IDENTIFIER ::= {
        iso(1) identified-organization(3) certicom(132) curve(0) 37 }

    secp521r1 OBJECT IDENTIFIER ::= {
        iso(1) identified-organization(3) certicom(132) curve(0) 35 }

    sect571k1 OBJECT IDENTIFIER ::= {
        iso(1) identified-organization(3) certicom(132) curve(0) 38 }

    sect571r1 OBJECT IDENTIFIER ::= {
        iso(1) identified-organization(3) certicom(132) curve(0) 39 }
algorithm确定后，再来看下subjectPublicKey，对ECC公钥来讲，subjectPublicKey就是ECPoint：

    ECPoint ::= OCTET STRING
是长度为65字节的OCTET STRING，其中第一个字节代表ECPoint是否经过压缩，如果为0x04，代表没有压缩。剩下的64个字节，前32个字节，表示ECPoint的X坐标，后32个字节表示ECPoint的Y坐标。

OCTET STRING类型的ECPoint在转换为BIT STRING类型的subjectPublicKey时，按照大端字节序转换。

ECC Public Key Example
我们以一个DER编码的ECC公钥为例，详细剖析一下X.509 ECC公钥的格式。公钥内容如下：

0x30 0x59 0x30 0x13 0x06 0x07
0x2a 0x86 0x48 0xce 0x3d 0x02
0x01 0x06 0x08 0x2a 0x86 0x48
0xce 0x3d 0x03 0x01 0x07 0x03
0x42 0x00 0x04 0x13 0x32 0x8e
0x0c 0x11 0x8a 0x70 0x1a 0x9e
0x18 0xa3 0xa9 0xa5 0x65 0xd8
0x41 0x68 0xce 0x2f 0x5b 0x11
0x94 0x57 0xec 0xe3 0x67 0x76
0x4a 0x3f 0xb9 0xec 0xd1 0x15
0xd0 0xf9 0x56 0x8b 0x15 0xe6
0x06 0x2d 0x72 0xa9 0x45 0x56
0x99 0xb0 0x9b 0xb5 0x30 0x90
0x8d 0x2e 0x31 0x0e 0x95 0x68
0xcc 0xcc 0x19 0x5c 0x65 0x53
0xba
通过前面的介绍，我们已经知道这是一个ASN.1格式的SubjectPublicKeyInfo的DER编码，是一个TLV类型的二进制数据。现在我们逐层解析下：

0x30 (SEQUENCE TAG: SubjectPublicKeyInfo) 0x59 (SEQUENCE LEN=89)
        0x30 (SEQUENCE TAG: AlgorithmIdentifier) 0x13 (SEQUENCE LEN=19)
                0x06 (OID TAG: Algorithm) 0x07 (OID LEN=7)
                        0x2a 0x86 0x48 0xce 0x3d 0x02 0x01 (OID VALUE="1.2.840.10045.2.1": ecPublicKey/Unrestricted Algorithm Identifier)
                0x06 (OID TAG: ECParameters:NamedCurve) 0x08 (OID LEN=8)
                        0x2a 0x86 0x48 0xce 0x3d 0x03 0x01 0x07 (OID VALUE="1.2.840.10045.3.1.7": Secp256r1/prime256v1)
        0x03 (BIT STRING TAG: SubjectPublicKey:ECPoint) 0x42 (BIT STRING LEN=66) 0x00 (填充bit数量为0)
                0x04 (未压缩的ECPoint)
                0x13 0x32 0x8e 0x0c 0x11 0x8a 0x70 0x1a 0x9e 0x18 0xa3 0xa9 0xa5 0x65 0xd8 0x41 0x68 0xce 0x2f 0x5b 0x11 0x94 0x57 0xec 0xe3 0x67 0x76 0x4a 0x3f 0xb9 0xec 0xd1 (ECPoint:X)
                0x15 0xd0 0xf9 0x56 0x8b 0x15 0xe6 0x06 0x2d 0x72 0xa9 0x45 0x56 0x99 0xb0 0x9b 0xb5 0x30 0x90 0x8d 0x2e 0x31 0x0e 0x95 0x68 0xcc 0xcc 0x19 0x5c 0x65 0x53 0xba (ECPoint:Y)
*/

//生成密钥对 未完善不建议使用
func GenerateEccKey() (pri string, pub string, err error) {
	//使用ecdsa生成密钥对
	privateKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	b64 := new(base64.Encoding)
	//使用509
	//private, err := x509.MarshalECPrivateKey(privateKey) //此处
	private := crypto.FromECDSA(privateKey)
	if err != nil {
		return "", "", err
	}
	//pem
	block := pem.Block{
		Type:  "esdsa private key",
		Bytes: private,
	}
	priFile := new(bytes.Buffer)
	pubFile := new(bytes.Buffer)
	if err != nil {
		return "", "", err
	}
	err = pem.Encode(priFile, &block)
	if err != nil {
		return "", "", err
	}
	pri = b64.EncodeToString(priFile.Bytes())
	//处理公钥
	//public := privateKey.PublicKey

	//x509序列化
	//publicKey, err := x509.MarshalPKIXPublicKey(&public)
	//if err != nil {
	//	return "", "", err
	//}
	publicKey := crypto.FromECDSAPub(&privateKey.PublicKey)
	//pem
	publicBlock := pem.Block{
		Type:  "ecdsa public key",
		Bytes: publicKey,
	}
	if err != nil {
		return "", "", err
	}
	//pem编码
	err = pem.Encode(pubFile, &publicBlock)
	if err != nil {
		return "", "", err
	}
	pub = b64.EncodeToString(pubFile.Bytes())
	return
}

//ecc签名--私钥  未完善不建议使用
func EccSignature(sourceData []byte, privateKey string) ([]byte, []byte) {

	////1,pem解密
	//block, _ := pem.Decode(privateKey)
	////x509解密
	//privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	//if err != nil {
	//	panic(err)
	//}
	////哈希运算
	//hashText := sha1.Sum(sourceData)
	////数字签名
	//r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashText[:])
	//if err != nil {
	//	panic(err)
	//}
	//rText, err := r.MarshalText()
	//if err != nil {
	//	panic(err)
	//}
	//sText, err := s.MarshalText()
	//if err != nil {
	//	panic(err)
	//}
	//defer file.Close()
	return nil, nil
}

//ecc认证  未完善不建议使用
func EccVerify(rText, sText, sourceData []byte, publicKeyFilePath string) bool {
	//读取公钥文件
	file, err := os.Open(publicKeyFilePath)
	if err != nil {
		panic(err)
	}
	info, err := file.Stat()
	if err != nil {
		panic(err)
	}
	buf := make([]byte, info.Size())
	file.Read(buf)
	//pem解码
	block, _ := pem.Decode(buf)

	//x509
	publicStream, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	//接口转换成公钥
	publicKey := publicStream.(*ecdsa.PublicKey)
	hashText := sha1.Sum(sourceData)
	var r, s big.Int
	r.UnmarshalText(rText)
	s.UnmarshalText(sText)
	//认证
	res := ecdsa.Verify(publicKey, hashText[:], &r, &s)
	defer file.Close()
	return res
}
