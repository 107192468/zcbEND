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
	"io"
	"io/ioutil"
	"math/big"
)

var RSA = &RSASecurity{}

type RSASecurity struct {
	pubStr string          //公钥字符串
	priStr string          //私钥字符串
	pubkey *rsa.PublicKey  //公钥
	prikey *rsa.PrivateKey //私钥
}

// 设置公钥
func (rsas *RSASecurity) SetPublicKey(pubStr string) (err error) {
	rsas.pubStr = pubStr
	rsas.pubkey, err = rsas.GetPublickey()
	return err
}

// 设置私钥
func (rsas *RSASecurity) SetPrivateKey(priStr string) (err error) {
	rsas.priStr = priStr
	rsas.prikey, err = rsas.GetPrivatekey()
	return err
}

// *rsa.PublicKey
func (rsas *RSASecurity) GetPrivatekey() (*rsa.PrivateKey, error) {
	return getPriKey([]byte(rsas.priStr))
}

// *rsa.PrivateKey
func (rsas *RSASecurity) GetPublickey() (*rsa.PublicKey, error) {
	return getPubKey([]byte(rsas.pubStr))
}

// 公钥加密
func (rsas *RSASecurity) PubKeyENCTYPT(input []byte) ([]byte, error) {
	if rsas.pubkey == nil {
		return []byte(""), errors.New(`Please set the public key in advance`)
	}
	output := bytes.NewBuffer(nil)
	err := pubKeyIO(rsas.pubkey, bytes.NewReader(input), output, true)
	if err != nil {
		return []byte(""), err
	}
	return ioutil.ReadAll(output)
}

// 公钥解密
func (rsas *RSASecurity) PubKeyDECRYPT(input []byte) ([]byte, error) {
	if rsas.pubkey == nil {
		return []byte(""), errors.New(`Please set the public key in advance`)
	}
	output := bytes.NewBuffer(nil)
	err := pubKeyIO(rsas.pubkey, bytes.NewReader(input), output, false)
	if err != nil {
		return []byte(""), err
	}
	return ioutil.ReadAll(output)
}

// 私钥加密
func (rsas *RSASecurity) PriKeyENCTYPT(input []byte) ([]byte, error) {
	if rsas.prikey == nil {
		return []byte(""), errors.New(`Please set the private key in advance`)
	}
	output := bytes.NewBuffer(nil)
	err := priKeyIO(rsas.prikey, bytes.NewReader(input), output, true)
	if err != nil {
		return []byte(""), err
	}
	return ioutil.ReadAll(output)
}

// 私钥解密
func (rsas *RSASecurity) PriKeyDECRYPT(input []byte) ([]byte, error) {
	if rsas.prikey == nil {
		return []byte(""), errors.New(`Please set the private key in advance`)
	}
	output := bytes.NewBuffer(nil)
	err := priKeyIO(rsas.prikey, bytes.NewReader(input), output, false)
	if err != nil {
		return []byte(""), err
	}

	return ioutil.ReadAll(output)
}

var (
	ErrDataToLarge     = errors.New("message too long for RSA public key size")
	ErrDataLen         = errors.New("data length error")
	ErrDataBroken      = errors.New("data broken, first byte is not zero")
	ErrKeyPairDismatch = errors.New("data is not encrypted by the private key")
	ErrDecryption      = errors.New("decryption error")
	ErrPublicKey       = errors.New("get public key error")
	ErrPrivateKey      = errors.New("get private key error")
)

// 设置公钥
func getPubKey(publickey []byte) (*rsa.PublicKey, error) {
	// decode public key
	block, _ := pem.Decode(publickey)
	if block == nil {
		return nil, errors.New("get public key error")
	}
	// x509 parse public key
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pub.(*rsa.PublicKey), err
}

// 设置私钥
func getPriKey(privatekey []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privatekey)
	if block == nil {
		return nil, errors.New("get private key error")
	}
	pri, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return pri, nil
	}
	pri2, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pri2.(*rsa.PrivateKey), nil
}

// 公钥加密或解密byte
func pubKeyByte(pub *rsa.PublicKey, in []byte, isEncrytp bool) ([]byte, error) {
	k := (pub.N.BitLen() + 7) / 8
	if isEncrytp {
		k = k - 11
	}
	if len(in) <= k {
		if isEncrytp {
			return rsa.EncryptPKCS1v15(rand.Reader, pub, in)
		} else {
			return pubKeyDecrypt(pub, in)
		}
	} else {
		iv := make([]byte, k)
		out := bytes.NewBuffer(iv)
		if err := pubKeyIO(pub, bytes.NewReader(in), out, isEncrytp); err != nil {
			return nil, err
		}
		return ioutil.ReadAll(out)
	}
}

// 私钥加密或解密byte
func priKeyByte(pri *rsa.PrivateKey, in []byte, isEncrytp bool) ([]byte, error) {
	k := (pri.N.BitLen() + 7) / 8
	if isEncrytp {
		k = k - 11
	}
	if len(in) <= k {
		if isEncrytp {
			return priKeyEncrypt(rand.Reader, pri, in)
		} else {
			return rsa.DecryptPKCS1v15(rand.Reader, pri, in)
		}
	} else {
		iv := make([]byte, k)
		out := bytes.NewBuffer(iv)
		if err := priKeyIO(pri, bytes.NewReader(in), out, isEncrytp); err != nil {
			return nil, err
		}
		return ioutil.ReadAll(out)
	}
}

// 公钥加密或解密Reader
func pubKeyIO(pub *rsa.PublicKey, in io.Reader, out io.Writer, isEncrytp bool) (err error) {
	k := (pub.N.BitLen() + 7) / 8
	if isEncrytp {
		k = k - 11
	}
	buf := make([]byte, k)
	var b []byte
	size := 0
	for {
		size, err = in.Read(buf)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if size < k {
			b = buf[:size]
		} else {
			b = buf
		}
		if isEncrytp {
			b, err = rsa.EncryptPKCS1v15(rand.Reader, pub, b)
		} else {
			b, err = pubKeyDecrypt(pub, b)
		}
		if err != nil {
			return err
		}
		if _, err = out.Write(b); err != nil {
			return err
		}
	}
	return nil
}

// 私钥加密或解密Reader
func priKeyIO(pri *rsa.PrivateKey, r io.Reader, w io.Writer, isEncrytp bool) (err error) {
	k := (pri.N.BitLen() + 7) / 8
	if isEncrytp {
		k = k - 11
	}
	buf := make([]byte, k)
	var b []byte
	size := 0
	for {
		size, err = r.Read(buf)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if size < k {
			b = buf[:size]
		} else {
			b = buf
		}
		if isEncrytp {
			b, err = priKeyEncrypt(rand.Reader, pri, b)
		} else {
			b, err = rsa.DecryptPKCS1v15(rand.Reader, pri, b)
		}
		if err != nil {
			return err
		}
		if _, err = w.Write(b); err != nil {
			return err
		}
	}
	return nil
}

// 公钥解密
func pubKeyDecrypt(pub *rsa.PublicKey, data []byte) ([]byte, error) {
	k := (pub.N.BitLen() + 7) / 8
	if k != len(data) {
		return nil, ErrDataLen
	}
	m := new(big.Int).SetBytes(data)
	if m.Cmp(pub.N) > 0 {
		return nil, ErrDataToLarge
	}
	m.Exp(m, big.NewInt(int64(pub.E)), pub.N)
	d := leftPad(m.Bytes(), k)
	if d[0] != 0 {
		return nil, ErrDataBroken
	}
	if d[1] != 0 && d[1] != 1 {
		return nil, ErrKeyPairDismatch
	}
	var i = 2
	for ; i < len(d); i++ {
		if d[i] == 0 {
			break
		}
	}
	i++
	if i == len(d) {
		return nil, nil
	}
	return d[i:], nil
}

// 私钥加密
func priKeyEncrypt(rand io.Reader, priv *rsa.PrivateKey, hashed []byte) ([]byte, error) {
	tLen := len(hashed)
	k := (priv.N.BitLen() + 7) / 8
	if k < tLen+11 {
		return nil, ErrDataLen
	}
	em := make([]byte, k)
	em[1] = 1
	for i := 2; i < k-tLen-1; i++ {
		em[i] = 0xff
	}
	copy(em[k-tLen:k], hashed)
	m := new(big.Int).SetBytes(em)
	c, err := decrypt(rand, priv, m)
	if err != nil {
		return nil, err
	}
	copyWithLeftPad(em, c.Bytes())
	return em, nil
}

// 从crypto/rsa复制
var bigZero = big.NewInt(0)
var bigOne = big.NewInt(1)

// 从crypto/rsa复制
func encrypt(c *big.Int, pub *rsa.PublicKey, m *big.Int) *big.Int {
	e := big.NewInt(int64(pub.E))
	c.Exp(m, e, pub.N)
	return c
}

// 从crypto/rsa复制
func decrypt(random io.Reader, priv *rsa.PrivateKey, c *big.Int) (m *big.Int, err error) {
	if c.Cmp(priv.N) > 0 {
		err = ErrDecryption
		return
	}
	var ir *big.Int
	if random != nil {
		var r *big.Int

		for {
			r, err = rand.Int(random, priv.N)
			if err != nil {
				return
			}
			if r.Cmp(bigZero) == 0 {
				r = bigOne
			}
			var ok bool
			ir, ok = modInverse(r, priv.N)
			if ok {
				break
			}
		}
		bigE := big.NewInt(int64(priv.E))
		rpowe := new(big.Int).Exp(r, bigE, priv.N)
		cCopy := new(big.Int).Set(c)
		cCopy.Mul(cCopy, rpowe)
		cCopy.Mod(cCopy, priv.N)
		c = cCopy
	}
	if priv.Precomputed.Dp == nil {
		m = new(big.Int).Exp(c, priv.D, priv.N)
	} else {
		m = new(big.Int).Exp(c, priv.Precomputed.Dp, priv.Primes[0])
		m2 := new(big.Int).Exp(c, priv.Precomputed.Dq, priv.Primes[1])
		m.Sub(m, m2)
		if m.Sign() < 0 {
			m.Add(m, priv.Primes[0])
		}
		m.Mul(m, priv.Precomputed.Qinv)
		m.Mod(m, priv.Primes[0])
		m.Mul(m, priv.Primes[1])
		m.Add(m, m2)

		for i, values := range priv.Precomputed.CRTValues {
			prime := priv.Primes[2+i]
			m2.Exp(c, values.Exp, prime)
			m2.Sub(m2, m)
			m2.Mul(m2, values.Coeff)
			m2.Mod(m2, prime)
			if m2.Sign() < 0 {
				m2.Add(m2, prime)
			}
			m2.Mul(m2, values.R)
			m.Add(m, m2)
		}
	}
	if ir != nil {
		m.Mul(m, ir)
		m.Mod(m, priv.N)
	}

	return
}

// 从crypto/rsa复制
func copyWithLeftPad(dest, src []byte) {
	numPaddingBytes := len(dest) - len(src)
	for i := 0; i < numPaddingBytes; i++ {
		dest[i] = 0
	}
	copy(dest[numPaddingBytes:], src)
}

// 从crypto/rsa复制
func nonZeroRandomBytes(s []byte, rand io.Reader) (err error) {
	_, err = io.ReadFull(rand, s)
	if err != nil {
		return
	}
	for i := 0; i < len(s); i++ {
		for s[i] == 0 {
			_, err = io.ReadFull(rand, s[i:i+1])
			if err != nil {
				return
			}
			s[i] ^= 0x42
		}
	}
	return
}

// 从crypto/rsa复制
func leftPad(input []byte, size int) (out []byte) {
	n := len(input)
	if n > size {
		n = size
	}
	out = make([]byte, size)
	copy(out[len(out)-n:], input)
	return
}

// 从crypto/rsa复制
func modInverse(a, n *big.Int) (ia *big.Int, ok bool) {
	g := new(big.Int)
	x := new(big.Int)
	y := new(big.Int)
	g.GCD(x, y, a, n)
	if g.Cmp(bigOne) != 0 {
		return
	}
	if x.Cmp(bigOne) < 0 {
		x.Add(x, n)
	}
	return x, true
}
